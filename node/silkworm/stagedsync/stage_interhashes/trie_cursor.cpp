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
    prefix_.reserve(40);  // Max size assignable is 40
    buffer_.reserve(96);  // Max size is 40 (TrieStorage prefix) + full unrolled nibbled key 32 == 82 (rounded to 96)
}

TrieCursor::move_operation_result TrieCursor::to_prefix(ByteView prefix) {
    // 0 bytes for TrieAccounts
    // 40 bytes (hashed address + incarnation) for TrieStorage
    if (size_t len{prefix.length()}; len != 0 && len != 40) {
        throw std::invalid_argument("Invalid prefix len : expected (0 || 40) whilst got " + std::to_string(len));
    }

    buffer_.clear();

    // Reset all SubNodes (we're starting a new tree)
    level_ = 0;
    for (auto& sub_node : sub_nodes_) {
        sub_node.reset();
    }
    auto& sub_node{sub_nodes_[level_]};

    prefix_.assign(prefix);  // Set the prefix and move on top of tree
    db_seek({});             // Try to locate root node of this tree

    if (!db_cursor_eof_ && db_cursor_key_.length() == 0) {
        // We've found a root record : proceed with parsing.
        sub_node.parse(db_cursor_key_, db_cursor_val_);
    } else {
        sub_node.child_id = 0;
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

    while (true) {
        auto& sub_node{sub_nodes_[level_]};
        if (sub_node.child_id > 0xf) {
            // This node is completely traversed - Ascend one level if possible
            if (level_ == 0) {
                return {};  // No higher level
            }
            sub_node.reset();                    // We leave this level so reset it
            sub_nodes_[--level_].child_id += 1;  // To next child of parent
            continue;
        }

        const Bytes full_key{sub_node.full_key()};
        const Bytes prefix_and_full_key{prefix_ + full_key};
        const bool has_changes{!changed_ || changed_->contains(prefix_and_full_key)};

        // Is this a node with a hash which can be used ?
        // If child_id == -1 then is a root node
        // If child_id != -1 then holds the hash of a leaf
        if (sub_node.has_hash() && !has_changes) {
            // Construct response ...
            move_operation_result ret{true, full_key, std::nullopt, sub_node.get_hash().value(), sub_node.has_tree()};
            // ... advance ...
            if (sub_node.child_id == -1) {
                sub_node.child_id = 0x10;  // Mark as fully traversed (next cycle will bump to next child of parent)
            } else {
                ++sub_node.child_id;  // To next child
            }
            // ... and return response
            return ret;
        }

        // From here onwards it does make sense to process only
        // for keys where child_id != -1. In fact only root nodes
        // can be skipped entirely if no changes
        if (sub_node.child_id == -1) {
            ++sub_node.child_id;
            continue;
        }

        // Do we have children in db ?
        // We must either rely on tree_mask (if node is loaded from db) or, if we're at level 0 (root)
        // search in any case as we might not have a node loaded.
        if ((!level_ && sub_node.value.empty()) || sub_node.has_tree()) {
            db_seek(full_key);
            if (!db_cursor_eof_) {
                auto& child_sub_node{sub_nodes_[++level_]};
                child_sub_node.parse(db_cursor_key_, db_cursor_val_);
                continue;
            }
        }

        // Something to process on this node ?
        if (!has_changes && !sub_node.has_state()) {
            ++sub_node.child_id;
            continue;
        }

        // Return to calling loop to process hashed states with current nibbled prefix
        move_operation_result ret{false, full_key, pack_nibbles(full_key), std::nullopt, false};
        ++sub_node.child_id;  // Increment for next cycle
        return ret;
    }
}

void TrieCursor::db_seek(ByteView seek_key) {
    db_cursor_eof_ = false;
    db_cursor_key_ = ByteView();
    db_cursor_val_ = ByteView();

    if (prefix_.empty()) {
        buffer_.assign(seek_key);
    } else {
        buffer_.assign(prefix_);
        buffer_.append(seek_key);
    }

    const auto buffer_slice{db::to_slice(buffer_)};
    auto data{buffer_.empty() ? db_cursor_.to_first(false) : db_cursor_.lower_bound(buffer_slice, false)};
    if (!data || !data.key.starts_with(buffer_slice)) {
        db_cursor_eof_ = true;
        return;
    }

    db_cursor_key_ = db::from_slice(data.key);       // Save db_cursor_ key ...
    db_cursor_key_.remove_prefix(prefix_.length());  // ... and remove prefix_ so we have node key
    db_cursor_val_ = db::from_slice(data.value);     // Save db_cursor_ value
}

void TrieCursor::collect_deletion(SubNode& sub_node) {
    if (!sub_node.deleted) {
        if (!sub_node.value.empty() && collector_) {
            buffer_.assign(prefix_);
            buffer_.append(sub_node.key);
            collector_->collect({Bytes(buffer_), Bytes{}});
        }
        sub_node.deleted = true;
    }
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
    child_id = -1;
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

bool TrieCursor::SubNode::has_tree() const { return (tree_mask & (1u << child_id)) != 0; }

bool TrieCursor::SubNode::has_hash() const {
    return child_id == -1 ? !root_hash.empty() : ((hash_mask & (1u << child_id)) != 0);
}

bool TrieCursor::SubNode::has_state() const { return (state_mask & (1u << child_id)) != 0; }

}  // namespace silkworm::trie
