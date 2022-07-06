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

#include <bitset>
#include <iostream>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/bits.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/trie/nibbles.hpp>

namespace silkworm::trie {

Cursor::Cursor(mdbx::cursor& db_cursor, PrefixSet& changed, etl::Collector* collector, ByteView prefix)
    : db_cursor_{db_cursor}, changed_{changed}, collector_{collector}, prefix_{prefix} {
    subnodes_.reserve(64);
    consume_node(/*key=*/{}, /*exact=*/true);
}

void Cursor::consume_node(ByteView key, bool exact) {
    const Bytes db_key{prefix_ + Bytes{key}};
    const auto db_data{exact ? db_cursor_.find(db::to_slice(db_key), /*throw_notfound=*/false)
                             : db_cursor_.lower_bound(db::to_slice(db_key), /*throw_notfound=*/false)};

    if (!exact) {
        if (!db_data) {
            // end-of-tree
            subnodes_.clear();
            return;
        }
        key = db::from_slice(db_data.key);
        if (!prefix_.empty()) {
            if (!key.starts_with(prefix_)) {
                subnodes_.clear();
                return;
            }
            key.remove_prefix(prefix_.length());
        }
    }

    std::optional<Node> node{std::nullopt};
    int nibble{-1};
    if (db_data) {
        node = Node::from_encoded_storage(db::from_slice(db_data.value));
        SILKWORM_ASSERT(node.has_value());
        SILKWORM_ASSERT(node->state_mask() != 0);
        if (!node->root_hash().has_value()) {
            nibble = ctz_16(node->state_mask()) - 1;
        }
    }

    if (!key.empty() && !subnodes_.empty()) {
        // the root might have nullopt node and thus no state bits, so we rely on the DB
        subnodes_[0].nibble = key[0];
    }

    subnodes_.push_back(SubNode{Bytes{key}, node, nibble});

    update_skip_state();

    // don't erase nodes with valid root hashes
    if (db_data && (!can_skip_state_ || nibble != -1)) {
        collector_->collect({Bytes{db::from_slice(db_data.key)}, Bytes{}});
    }
}

void Cursor::next() {
    if (subnodes_.empty()) {
        // end-of-tree
        return;
    }

    auto& sub_node{subnodes_.back()};
    if (!can_skip_state_ && sub_node.tree_flag()) {
        // go to the child node
        if (sub_node.nibble < 0) {
            move_to_next_sibling(/*allow_root_to_child_nibble_within_subnode=*/true);
        } else {
            consume_node(sub_node.full_key(), /*exact=*/false);
            return;  // ^^ already updates skip state
        }
    } else {
        move_to_next_sibling(/*allow_root_to_child_nibble_within_subnode=*/false);
    }

    update_skip_state();
}

void Cursor::update_skip_state() {
    const std::optional<Bytes> k{key()};
    if (!k.has_value() || changed_.contains(prefix_ + k.value())) {
        can_skip_state_ = false;
    } else {
        can_skip_state_ = subnodes_.back().hash_flag();
    }
}

void Cursor::move_to_next_sibling(bool allow_root_to_child_nibble_within_subnode) {
    while (!subnodes_.empty()) {
        SubNode& sub_node{subnodes_.back()};

        if (sub_node.nibble >= 0xF || (sub_node.nibble == -1 && !allow_root_to_child_nibble_within_subnode)) {
            // this node is fully traversed
            subnodes_.pop_back();
            allow_root_to_child_nibble_within_subnode = false;
            continue;
        }

        ++sub_node.nibble;

        if (!sub_node.node.has_value()) {
            // we can't rely on the state flag, so search in the DB
            consume_node(sub_node.full_key(), /*exact=*/false);
            return;
        }

        for (; sub_node.nibble < 0x10; ++sub_node.nibble) {
            if (sub_node.node->state_mask() & (1u << sub_node.nibble)) {
                return;
            }
        }

        // this node is fully traversed
        subnodes_.pop_back();
        allow_root_to_child_nibble_within_subnode = false;
    }
}

Bytes Cursor::SubNode::full_key() const {
    Bytes out{key};
    if (nibble != -1) {
        out.push_back(nibble);
    }
    return out;
}

bool Cursor::SubNode::tree_flag() const {
    if (nibble < 0 || !node.has_value()) {
        return true;
    }
    return node->tree_mask() & (1u << nibble);
}

bool Cursor::SubNode::hash_flag() const {
    if (!node.has_value()) {
        return false;
    }
    return nibble == -1 ? node->root_hash().has_value() : node->hash_mask() & (1u << nibble);
}

const evmc::bytes32* Cursor::SubNode::hash() const {
    if (!hash_flag()) {
        return nullptr;
    }

    if (nibble < 0) {
        return &node->root_hash().value();
    }

    const unsigned first_nibbles_mask{(1u << nibble) - 1};
    const size_t hash_idx{popcount_16(node->hash_mask() & first_nibbles_mask)};
    return &node->hashes()[hash_idx];
}

std::optional<Bytes> Cursor::key() const {
    if (subnodes_.empty()) {
        return std::nullopt;
    }
    return subnodes_.back().full_key();
}

const evmc::bytes32* Cursor::hash() const {
    if (subnodes_.empty()) {
        return nullptr;
    }
    return subnodes_.back().hash();
}

bool Cursor::children_are_in_trie() const {
    if (subnodes_.empty()) {
        return false;
    }
    return subnodes_.back().tree_flag();
}

std::optional<Bytes> Cursor::first_uncovered_prefix() const {
    std::optional<Bytes> k{key()};
    if (can_skip_state_ && k.has_value()) {
        k = increment_nibbled_key(*k);
    }
    if (!k.has_value()) {
        return std::nullopt;
    }
    return pack_nibbles(*k);
}

std::optional<Bytes> increment_nibbled_key(ByteView nibbles) {
    if (nibbles.empty()) {
        return std::nullopt;
    }

    auto rit{std::find_if(nibbles.rbegin(), nibbles.rend(), [](uint8_t nibble) { return nibble < 0xf; })};
    if (rit == nibbles.rend()) {
        return std::nullopt;
    }

    auto count{static_cast<size_t>(std::distance(nibbles.begin(), rit.base()))};
    Bytes ret{nibbles.substr(0, count)};
    ++ret.back();
    return ret;
}

TrieCursor::TrieCursor(mdbx::cursor& db_cursor, PrefixSet& changed, etl::Collector* collector)
    : db_cursor_(db_cursor), changed_{changed}, collector_{collector} {
    prefix_.reserve(40);    // Max size assignable is 40
    buffer_.reserve(96);    // Max size is 40 (TrieStorage prefix) + full unrolled nibbled key 32 == 82 (rounded to 96)
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

    prefix_.assign(prefix);  // Set the prefix and move on top of tree
    db_seek({});             // Moves db_cursor_ on top of *existing* (if any) trie

    if (!db_cursor_eof_) {
        // We've found a record : proceed with parsing.
        level_ = db_cursor_key_.length();
        auto& sub_node{sub_nodes_[level_]};
        sub_node.parse(db_cursor_key_, db_cursor_val_);
        if (level_ > 0) {
            sub_nodes_[0].child_id = static_cast<int8_t>(sub_node.key[0]);
        }
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
            sub_node.reset();  // We leave this level so reset it
            if (level_ == 0) {
                // No higher level
                return {false, std::nullopt, std::nullopt, std::nullopt, false};
            }
            sub_nodes_[--level_].child_id += 1;  // To next child of parent
            continue;
        }

        const Bytes full_key{sub_node.full_key()};
        const Bytes prefix_and_full_key{prefix_ + full_key};
        const bool has_changes{changed_.contains(prefix_and_full_key)};

        /*
                static const Bytes debug_key{*from_hex("0x0008020506000e")};
                if (full_key == debug_key) {
                    auto changed{changed_.find_contains(prefix_and_full_key)};
                    std::cout << "Key=" << to_hex(full_key, true)
                              << " has_value=" << (sub_node.value.empty() ? "false" : "true")
                              << " child_id=" << std::to_string(sub_node.child_id)
                              << " state_mask=" << std::bitset<16>(sub_node.state_mask)
                              << " tree_mask=" << std::bitset<16>(sub_node.tree_mask)
                              << " hash_mask=" << std::bitset<16>(sub_node.hash_mask)
                              << " has_hash=" << (sub_node.has_hash() ? "true" : "false")
                              << " changes=" << (has_changes ? "true" : "false") << " changed=" << to_hex(changed, true)
                              << std::endl;
                    SILKWORM_ASSERT(true == false);
                }
        */

        // std::cout << "Level=" << std::to_string(level_) << " key=" << to_hex(full_key) << std::endl;

        // Is this a node with a hash which can be used ?
        // If child_id == -1 then is a root node
        // If child_id != -1 then holds the hash of a leaf
        if (sub_node.has_hash() && !has_changes) {
            // Construct response ...
            move_operation_result ret{true, full_key, std::nullopt, sub_node.get_hash().value(), sub_node.has_tree()};
            // ... advance ...
            if (sub_node.child_id == -1) {
                sub_node.child_id = 0xf;  // Mark as traversed (next cycle will bump to next child of parent)
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
        // Firstly we check whether result from previous seek
        // has data in the path: should we find data then descend
        // one level and restart. This prevents multiple lookups of same key
        // Eventually look in db for a child
        if (sub_node.has_tree()) {
            db_seek(full_key);
            SILKWORM_ASSERT(!db_cursor_eof_);

            auto& new_sub_node{sub_nodes_[++level_]};
            new_sub_node.parse(db_cursor_key_, db_cursor_val_);
            continue;
        }

        // Node has no children to inspect so there are no sub-hashes
        // If this key is in changed list then we cannot skip it.
        // Return to calling loop to process all hashed states with current
        // nibbled prefix.
        if (has_changes || sub_node.has_state()) {

            move_operation_result ret{false, full_key, pack_nibbles(full_key), std::nullopt, false};

            // Erase the node (if in db) as it will be recomputed
            // Note ! This is not a root node (if we're here it means child_id != -1)
            collect_deletion(sub_node);

            ++sub_node.child_id;  // Increment for next cycle
            return ret;
        }

        ++sub_node.child_id;  // Simply increment
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

    auto buffer_slice{db::to_slice(buffer_)};
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

bool TrieCursor::SubNode::has_tree() const { return (child_id == -1 || (tree_mask & (1u << child_id)) != 0); }

bool TrieCursor::SubNode::has_hash() const {
    return child_id == -1 ? !root_hash.empty() : ((hash_mask & (1u << child_id)) != 0);
}

bool TrieCursor::SubNode::has_state() const { return (state_mask & (1u << child_id)) != 0; }

}  // namespace silkworm::trie
