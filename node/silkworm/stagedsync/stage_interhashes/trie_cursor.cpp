/*
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

           http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "trie_cursor.hpp"

#include <iostream>

#include <silkworm/common/bits.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/trie/nibbles.hpp>

namespace silkworm::trie {

TrieCursor::TrieCursor(mdbx::cursor& db_cursor, PrefixSet* changed, etl::Collector* collector)
    : db_cursor_(db_cursor), changed_{changed}, collector_{collector} {
    curr_key_.reserve(40);
    prev_key_.reserve(40);
    prefix_.reserve(40);  // Max size assignable is 40
    buffer_.reserve(96);  // Max size is 40 (TrieStorage prefix) + full unrolled nibbled key 32 == 82 (rounded to 96)
}

TrieCursor::move_operation_result TrieCursor::to_prefix(ByteView prefix) {
    // 0 bytes for TrieAccounts
    // 40 bytes (hashed address + incarnation) for TrieStorage
    if (size_t len{prefix.length()}; len != 0 && len != 40) {
        throw std::invalid_argument("Invalid prefix len : expected (0 || 40) whilst got " + std::to_string(len));
    }
    prefix_.assign(prefix);

    buffer_.clear();
    curr_key_.clear();
    prev_key_.clear();

    // Reset all SubNodes (we're starting a new tree)
    level_ = 0;
    for (auto& sub_node : sub_nodes_) {
        sub_node.reset();
    }

    if (changed_) {
        buffer_.assign(prefix_);
        auto [_, next_created]{changed_->contains_and_next_marked({})};
        next_created_ = next_created;
    }

    if (db_seek({}) && consume_current()) {
        auto& node{sub_nodes_[level_]};
        return {skip_state_, curr_key_, std::nullopt, node.get_hash(), node.has_tree()};
    }
    return to_next();
}

TrieCursor::move_operation_result TrieCursor::to_next() {
    /*
     * We process node's nibbled keys in ascending lexicographical order
     * 0x00
     * 0x0000
     * 0x0001
     * 0x000100
     * [...]
     * 0x000f
     * 0x01
     *
     * Requirements for going down are either
     * - sub_node has child in db
     * - sub_node child key is prefix of next node in db
     * - sub_node child key is contained in changed list
     */

    skip_state_ = true;
    prev_key_.assign(curr_key_);
    curr_key_.clear();

    while (true) {
        auto& sub_node{sub_nodes_[level_]};
        ++sub_node.child_id;

        // When node is completely traversed ascend one level if possible
        // Note ! We don't have intermediate ephemeral nodes as in Erigon
        if (sub_node.child_id > sub_node.max_child_id) {
            if (level_ == 0) {
                skip_state_ = false;
                return {};  // No higher level
            }
            sub_node.reset();                    // We leave this level so reset it
            --level_;
            continue;
        }

        const Bytes full_key{sub_node.full_key()};
        const Bytes prefix_and_full_key{prefix_ + full_key};

        // Consume node
        if (sub_node.has_hash()) {
            buffer_.assign(prefix_and_full_key);
            if (changed_) {
                auto [has_changes, next_created]{changed_->contains_and_next_marked(buffer_)};
                if (!has_changes) {
                    skip_state_ = skip_state_ && key_is_before(buffer_, next_created_);
                    next_created_ = next_created;
                    curr_key_.assign(full_key);

                    // Construct response ...
                    move_operation_result ret{skip_state_, full_key, std::nullopt, sub_node.get_hash().value(),
                                              sub_node.has_tree()};
                    // ... advance for next cycle ...
                    if (sub_node.child_id == -1) {
                        // Mark this root node as fully traversed (next cycle will bump to next child of parent)
                        sub_node.child_id = sub_node.max_child_id + 1;
                    } else {
                        // To next child
                        ++sub_node.child_id;
                    }
                    // ... and return response
                    return ret;
                }
            }
        }
        db_delete(sub_node);

        //        const bool has_changes{!changed_ || changed_->contains(prefix_and_full_key)};
        //
        //        // Is this a node with a hash which can be used ?
        //        // If child_id == -1 then is a root node
        //        // If child_id != -1 then holds the hash of a leaf
        //        if (sub_node.has_hash() && !has_changes) {
        //            // Construct response ...
        //            move_operation_result ret{true, full_key, std::nullopt, sub_node.get_hash().value(),
        //            sub_node.has_tree()};
        //            // ... advance ...
        //            if (sub_node.child_id == -1) {
        //                sub_node.child_id = 0x10;  // Mark as fully traversed (next cycle will bump to next child of
        //                parent)
        //            } else {
        //                ++sub_node.child_id;  // To next child
        //            }
        //            // ... and return response
        //            return ret;
        //        }

        // From here onwards it does make sense to process only
        // for keys where child_id != -1. In fact only root nodes
        // can be skipped entirely if no changes
        if (sub_node.child_id == -1) {
            ++sub_node.child_id;
            continue;
        }

        // Do we have children in db ?
        // We must either rely on tree_mask (if node is loaded from db) or search anyway if ephemeral node
        if (sub_node.has_tree()) {
            skip_state_ = skip_state_ && true;
            if (db_seek(full_key)) {
                continue;
            }
        } else {
            skip_state_ = skip_state_ && false;
        }
        ++sub_node.child_id;

        //        // Something to process on this node ?
        //        if (!has_changes && !sub_node.has_state()) {
        //            ++sub_node.child_id;
        //            continue;
        //        }
        //
        //        // Return to calling loop to process hashed states with current nibbled prefix
        //        move_operation_result ret{false, full_key, pack_nibbles(full_key), std::nullopt, false};
        //        ++sub_node.child_id;  // Increment for next cycle
        //        return ret;
    }
}

bool TrieCursor::db_seek(ByteView seek_key) {
    if (prefix_.empty()) {
        buffer_.assign(seek_key);
    } else {
        buffer_.assign(prefix_);
        buffer_.append(seek_key);
    }

    const auto buffer_slice{db::to_slice(buffer_)};
    auto data{buffer_.empty() ? db_cursor_.to_first(false) : db_cursor_.lower_bound(buffer_slice, false)};
    if (!data || !data.key.starts_with(buffer_slice)) {
        return false;
    }

    ByteView db_cursor_key{db::from_slice(data.key)};  // Save db_cursor_ key ...
    db_cursor_key.remove_prefix(prefix_.length());     // ... and remove prefix_ so we have node key
    if (seek_key.empty() && !db_cursor_key.empty()) {
        // Note ! an empty seek_key means we're looking for a root node with empty key
        return false;
    }

    ByteView db_cursor_val{db::from_slice(data.value)};  // Save db_cursor_ value
    level_ += seek_key.empty() ? 0 : 1;                  // Down one level for child node. Stay at zero for root node
    auto& new_node{sub_nodes_[level_]};
    new_node.parse(db_cursor_key, db_cursor_val);
    return true;
}

void TrieCursor::db_delete(SubNode& node) {
    if (!node.deleted) {
        if (!node.value.empty() && collector_) {
            buffer_.assign(prefix_);
            buffer_.append(node.key);
            collector_->collect({Bytes(buffer_), Bytes{}});
        }
        node.deleted = true;
    }
}
bool TrieCursor::consume_current() {
    auto& node{sub_nodes_[level_]};
    if (node.has_hash()) {
        if (prefix_.empty()) {
            buffer_.assign(node.full_key());
        } else {
            buffer_.assign(prefix_);
            buffer_.append(node.full_key());
        }
        if (changed_) {
            auto [has_changes, next_created]{changed_->contains_and_next_marked(buffer_)};
            if (!has_changes) {
                skip_state_ = skip_state_ && key_is_before(buffer_, next_created_);
                next_created_ = next_created;
                curr_key_.assign(buffer_.substr(prefix_.size()));
                return true;
            }
        }
    }
    db_delete(node);
    return false;
}

bool TrieCursor::key_is_before(ByteView k1, ByteView k2) {
    if (k1.is_null()) {
        return false;
    }
    if (k2.is_null()) {
        return true;
    }
    return k1 < k2;
}
bool TrieCursor::next_sibling_of_current() {
    auto& node{sub_nodes_[level_]};
    while (node.child_id < node.max_child_id) {
        ++node.child_id;
        if (node.has_hash() || node.has_tree()) {
            return true;
        }
        if (node.has_state()) {
            skip_state_ = false;
        }
    }
    return false;
}
bool TrieCursor::next_sibling_of_parent() {
    while (level_) {
        --level_;
        if (next_sibling_of_current()) {
            return true;
        }
    }
    return false;
}

void TrieCursor::SubNode::reset() {
    key.clear();
    value = ByteView();
    root_hash = ByteView();
    hashes = ByteView();
    state_mask = 0;
    tree_mask = 0;
    hash_mask = 0;
    child_id = -1;
    max_child_id = 0xf;  // Traverse all node for ephemeral ones.
    deleted = false;
}

void TrieCursor::SubNode::parse(ByteView k, ByteView v) {
    // At least state/tree/hash masks need to be present
    if (v.length() < 6) {
        throw std::invalid_argument("wrong node raw length: expected >= 6 got " + std::to_string(v.length()));
    }
    // Beyond the 6th byte the length must be a multiple of kHashLength
    if ((v.length() - 6) % kHashLength != 0) {
        throw std::invalid_argument("wrong node raw hashes length: not a multiple of " + std::to_string(kHashLength));
    }

    key.assign(k);
    value = v;
    hashes = v.substr(6);
    state_mask = endian::load_big_u16(&v[0]);
    tree_mask = endian::load_big_u16(&v[2]);
    hash_mask = endian::load_big_u16(&v[4]);

    if (!is_subset(tree_mask, state_mask)) {
        throw std::invalid_argument("tree mask not subset of state mask");
    }
    if (!is_subset(hash_mask, state_mask)) {
        throw std::invalid_argument("hash mask not subset of state mask");
    }

    if (hashes.length() % kHashLength != 0) {
        throw std::invalid_argument("malformed hashes payload (not multiple of " + std::to_string(kHashLength) + ")");
    }

    size_t expected_hashes_count{popcount_16(hash_mask)};
    size_t effective_hashes_count{hashes.length() / kHashLength};
    if (effective_hashes_count == (expected_hashes_count + 1)) {
        root_hash = hashes.substr(0, kHashLength);
        hashes.remove_prefix(kHashLength);
    } else if (effective_hashes_count == expected_hashes_count) {
        root_hash = ByteView();
    } else {
        // Wrong number of hashes
        throw std::invalid_argument("invalid hashes count expected " + std::to_string(expected_hashes_count) +
                                    "[+1] got " + std::to_string(effective_hashes_count));
    }

    deleted = false;
    child_id = static_cast<int8_t>(ctz_16(state_mask)) - 1;
    max_child_id = static_cast<int8_t>(bitlen_16(state_mask));
}

Bytes TrieCursor::SubNode::full_key() const {
    Bytes ret{key};
    if (child_id != -1) {
        ret.push_back(static_cast<uint8_t>(child_id));
    }
    return ret;
}

std::optional<Bytes> TrieCursor::SubNode::get_hash() const {
    if (!has_hash()) {
        return std::nullopt;
    }
    if (child_id == -1) {
        return Bytes(root_hash);
    }
    const unsigned first_nibbles_mask{(1u << child_id) - 1};
    const size_t hash_idx{popcount_16(hash_mask & first_nibbles_mask)};
    return Bytes(hashes.substr(kHashLength * hash_idx, kHashLength));
}

bool TrieCursor::SubNode::has_tree() const { return (value.empty() || tree_mask & (1u << child_id)) != 0; }

bool TrieCursor::SubNode::has_hash() const {
    return child_id == -1 ? !root_hash.empty() : ((hash_mask & (1u << child_id)) != 0);
}

bool TrieCursor::SubNode::has_state() const { return (state_mask & (1u << child_id)) != 0; }

}  // namespace silkworm::trie
