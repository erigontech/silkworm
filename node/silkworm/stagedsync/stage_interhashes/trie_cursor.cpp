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

#include <silkworm/common/bits.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/trie/nibbles.hpp>

namespace silkworm::trie {

TrieCursor::TrieCursor(mdbx::cursor& db_cursor, PrefixSet* changed, etl::Collector* collector)
    : db_cursor_(db_cursor), changed_list_{changed}, collector_{collector} {
    curr_key_.reserve(64);
    prev_key_.reserve(64);
    prefix_.reserve(64);
    buffer_.reserve(128);
}

TrieCursor::move_operation_result TrieCursor::to_prefix(ByteView prefix) {
    // 0 bytes for TrieAccounts
    // 40 bytes (hashed address + incarnation) for TrieStorage
    if (size_t len{prefix.length()}; len != 0 && len != db::kHashedStoragePrefixLength) {
        throw std::invalid_argument("Invalid prefix len : expected (0 || 40) whilst got " + std::to_string(len));
    }
    prefix_.assign(prefix);

    buffer_.clear();
    curr_key_.clear();
    prev_key_.clear();
    next_created_ = ByteView{};
    end_of_tree_ = false;
    skip_state_ = true;

    // Reset all SubNodes (we're starting a new tree)
    // from currently used to top
    sub_nodes_[level_].reset();
    while (level_ != 0) {
        sub_nodes_[--level_].reset();
    }

    // Check changed list contains requested prefix_ and retrieve the first created account under "that" trie
    // This also returns the first "created" account in "that" trie
    bool has_changes{changed_list_ == nullptr};  // Full regeneration: everything is changed
    if (!has_changes) {
        std::tie(has_changes, next_created_) = changed_list_->contains_and_next_marked(prefix_);
    }

    // Lookup for a root node
    // Assumption: an existing trie MUST have its root node
    // If it doesn't exist we assume the whole trie must be rebuilt from scratch
    if (db_seek({})) {
        // Found a root node - use its root hash only if no changes
        // Otherwise this root can be marked for deletion as it needs
        // to be reconstructed and eventually begin the child_id loop
        auto& node{sub_nodes_[level_]};
        if (node.root_hash.is_null()) {
            throw std::logic_error("Trie integrity failure. Requested root node with key " +
                                   to_hex(node.full_key(), true) + " has no root_hash");
        }
        if (!has_changes) {
            end_of_tree_ = true;  // We don't need to further traverse this trie
            return {skip_state_, curr_key_, Bytes(node.root_hash), false};
        }
        db_delete(node);
    } else {
        skip_state_ = false;
        end_of_tree_ = true;
        return {skip_state_, std::nullopt, std::nullopt, false, Bytes{}};
    }

    // Begin looping child_ids (we have found a root node but has changes)
    return to_next();
}

TrieCursor::move_operation_result TrieCursor::to_next() {
    /*
     * We process node's nibbled keys in ascending lexicographical order
     * 0x
     * 0x00
     * 0x0000
     * 0x0001
     * 0x000100
     * [...]
     * 0x000f
     * 0x01
     *
     * When AtPrefix is executed it tries to locate the root node of the tree
     * If found (and no changes) then it returns the root hash. Otherwise, the to_next cycle is triggered.
     * On every to_next we
     *  1) Point to the node of current level_ and step on next child
     *  2) If step operation returns false it means we have exhausted all child_ids which have a state. As a result we
     *     try to go up one level (if possible) and goto 1)
     *  3) If node has_hash return node.full_key and bound hash (it will be added as a branch node in hash builder).
     *     If skip_state==false also return the previous nibbled key after increment
     *     This will cause to process state of all previous hashed accounts as leaves *and* the branch node.
     *  4) If  node does not have hash but has_tree try to locate child node.
     *     If found descend one level (++level) and goto 1)
     *  5) If node has_state set skip_state to false
     *  6) goto 1)
     *
     *  Note ! In absence of a root node then node at level 0 is always an ephemeral node (it does not have any value
     *  loaded from db) and for all child_ids it has always has_tree and has_state
     */

    if (end_of_tree_) {
        throw std::domain_error("Can't move next beyond the end of tree");
    }

    skip_state_ = true;
    std::swap(prev_key_, curr_key_);
    curr_key_.clear();

    while (!end_of_tree_) {
        auto& sub_node{sub_nodes_[level_]};
        ++sub_node.child_id;  // Advance to next child_id. (Note we start from -1 so "first next" is 0)
        sub_node.hash_id += static_cast<int>(sub_node.has_hash());

        // On reach of max_child_id the node is completely traversed :
        // ascend one level, if possible, or mark the end of the tree (completely traversed)
        // Note ! We don't have intermediate "empty" nodes as in Erigon
        if (sub_node.child_id == sub_node.max_child_id) {
            sub_node.reset();
            if (level_) {
                --level_;
            } else {
                end_of_tree_ = true;
            }
            continue;
        }

        // Consume node's hash (if any)
        if (consume(sub_node)) {
            curr_key_.assign(sub_node.full_key());
            return {skip_state_, curr_key_, sub_node.hash(), sub_node.has_tree(), first_uncovered()};
        }

        // If a child is expected we MUST find it. db_seek also descends one level
        // If not found it means the tree is corrupted
        if (sub_node.has_tree()) {
            if (!db_seek(sub_node.full_key())) {
                throw std::logic_error(
                    "Trie integrity failure. Missing child for node key=" + to_hex(sub_node.key, true) +
                    " child_id=" + std::to_string(static_cast<uint32_t>(sub_node.child_id)));
            }
        } else {
            skip_state_ = false;
        }

        if (sub_node.has_state()) {
            skip_state_ = false;
        }
    }

    auto next{increment_nibbled_key(prev_key_)};
    skip_state_ = skip_state_ && (next == std::nullopt);
    return {skip_state_, std::nullopt, std::nullopt, false, first_uncovered()};  // No higher level
}

bool TrieCursor::db_seek(ByteView seek_key) {
    buffer_.assign(prefix_).append(seek_key);
    const auto buffer_slice{db::to_slice(buffer_)};
    auto data{buffer_.empty() ? db_cursor_.to_first(false) : db_cursor_.lower_bound(buffer_slice, false)};
    if (!data || !data.key.starts_with(buffer_slice)) {
        return false;
    }

    ByteView db_cursor_key{db::from_slice(data.key)};  // Save db_cursor_ key ...
    db_cursor_key.remove_prefix(prefix_.length());     // ... and remove prefix_ so we have node key
    if (seek_key.empty() && !db_cursor_key.empty()) {
        // Note ! an empty seek_key means we're looking for a root node with empty key which does not exist
        return false;
    }

    ByteView db_cursor_val{db::from_slice(data.value)};  // Save db_cursor_ value
    level_ += seek_key.empty() ? 0 : 1u;                 // Down one level for child node. Stay at zero for root node
    auto& new_node{sub_nodes_[level_]};
    new_node.parse(db_cursor_key, db_cursor_val);
    return true;
}

void TrieCursor::db_delete(SubNode& node) {
    if (!node.deleted && collector_) {
        buffer_.assign(prefix_).append(node.key);
        collector_->collect({buffer_, Bytes{}});
        node.deleted = true;
    }
}

bool TrieCursor::consume(SubNode& node) {
    if (node.has_hash()) {
        buffer_.assign(prefix_).append(node.full_key());
        auto [has_changes, next_created]{changed_list_->contains_and_next_marked(buffer_)};
        if (!has_changes) {
            skip_state_ = skip_state_ && key_is_before(buffer_, next_created_);
            std::swap(next_created_, next_created);
            return true;
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
std::optional<Bytes> TrieCursor::increment_nibbled_key(const ByteView origin) {
    Bytes ret{};
    auto rit{std::find_if(origin.rbegin(), origin.rend(), [](uint8_t nibble) { return nibble != 0xf; })};
    if (rit == origin.rend()) {
        // Overflow
        return std::nullopt;
    }
    auto count{static_cast<size_t>(std::distance(origin.begin(), rit.base()))};
    ret.assign(origin.substr(0, count));
    ++ret.back();
    return ret;
}
std::optional<Bytes> TrieCursor::first_uncovered() {
    if (skip_state_) {
        return std::nullopt;
    }

    // This is intended. Don't want an empty origin to be marked as overflown
    if (prev_key_.empty()) {
        return prev_key_;
    }

    const auto incremented_nibbled_key{increment_nibbled_key(prev_key_)};
    if (incremented_nibbled_key.has_value()) {
        return pack_nibbles(incremented_nibbled_key.value());
    }
    return incremented_nibbled_key;
}

void TrieCursor::SubNode::reset() {
    key = ByteView();
    value = ByteView();
    root_hash = ByteView();
    hashes = ByteView();
    state_mask = 0;
    tree_mask = 0;
    hash_mask = 0;
    child_id = -1;
    max_child_id = 0x10;  // Traverse all node for ephemeral ones.
    hash_id = -1;
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

    key = k;
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
    hashes_count = hashes.length() / kHashLength;
    if (hashes_count == (expected_hashes_count + 1)) {
        root_hash = hashes.substr(0, kHashLength);
        hashes.remove_prefix(kHashLength);
        --hashes_count;
    } else if (hashes_count != expected_hashes_count) {
        // Wrong number of hashes
        throw std::invalid_argument("invalid hashes count expected " + std::to_string(expected_hashes_count) + " got " +
                                    std::to_string(hashes_count));
    }

    child_id = static_cast<int8_t>(ctz_16(state_mask)) - 1;
    max_child_id = static_cast<int8_t>(bitlen_16(state_mask));
}

Bytes TrieCursor::SubNode::full_key() const noexcept {
    Bytes ret{key};
    if (child_id != -1) {
        ret.push_back(static_cast<uint8_t>(child_id));
    }
    return ret;
}

Bytes TrieCursor::SubNode::hash() const {
    if (hash_id < 0 || static_cast<uint32_t>(hash_id) >= hashes_count) {
        throw std::out_of_range("Hash id out of bounds");
    }
    return Bytes(hashes.substr(kHashLength * static_cast<size_t>(hash_id), kHashLength));
}

bool TrieCursor::SubNode::has_tree() const noexcept { return (tree_mask & (1u << child_id)) != 0; }

bool TrieCursor::SubNode::has_hash() const noexcept { return (hash_mask & (1u << child_id)) != 0; }

bool TrieCursor::SubNode::has_state() const noexcept { return (state_mask & (1u << child_id)) != 0; }

}  // namespace silkworm::trie
