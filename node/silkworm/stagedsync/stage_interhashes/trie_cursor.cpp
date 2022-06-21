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

        if (sub_node.nibble >= 0xF || (sub_node.nibble < 0 && !allow_root_to_child_nibble_within_subnode)) {
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
    if (nibble < 0) {
        return node->root_hash().has_value();
    }
    return node->hash_mask() & (1u << nibble);
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

AccCursor::AccCursor(mdbx::cursor& db_cursor, PrefixSet& changed, etl::Collector* collector)
    : db_cursor_{db_cursor}, changed_{changed}, collector_{collector} {
    prefix_.reserve(64);
    prev_.reserve(64);
    curr_.reserve(64);
    next_.reserve(64);
    buff_.reserve(64);
}

AccCursor::move_operation_result AccCursor::to_prefix(ByteView prefix) {
    // 0 bytes for TrieAccounts
    // 40 bytes (hashed address + incarnation) for TrieStorage
    if (size_t len{prefix.length()}; len != 0 && len != 40) {
        throw std::invalid_argument("Invalid prefix len : expected 0 || 40 got" + std::to_string(len));
    }

    // Reset every subnode
    for (auto& sub_node : sub_nodes_) {
        sub_node.reset();
    }

    skip_state_ = true;
    prev_.assign(curr_);
    first_uncovered_ = increment_nibbled_key(prev_);
    prefix_.assign(prefix);  // Store prefix (all db searches will account that)

    // We query for root node (len == 0) in changed list
    // Even if counter-intuitive this tells which is the next nibbled key being created
    // Changed list contains the FULL db key
    buff_.assign(prefix_);
    auto [in_changed_list, next_created]{changed_.contains_and_next_marked(buff_)};
    next_created_.assign(next_created.substr(prefix.length()));

    // We look for root (len = 0) into db
    // prefix is taken into account in db:seek
    if (!db_seek({}, {})) {
        curr_.clear();
        skip_state_ = false;
        return {};
    }

    // For TrieStorage we might find storage root
    if (auto& sub_node{sub_nodes_[level_]}; sub_node.root_hash.empty() == false) {
        if (!in_changed_list) {
            skip_state_ = true;
            curr_.assign(sub_node.key);
            return {curr_, Bytes(sub_node.root_hash), false};
        }
        delete_current();
        preorder_traversal_step_no_indepth();
        return {Bytes{}, std::nullopt, false};
    }

    if (consume()) {
        return {curr_, Bytes(hash(sub_nodes_[level_].hash_id)), has_tree()};
    }
    return next_sibling();
}

AccCursor::move_operation_result AccCursor::to_next() {
    skip_state_ = true;
    prev_.assign(curr_);
    first_uncovered_ = increment_nibbled_key(prev_);

    preorder_traversal_step_no_indepth();

    if (sub_nodes_[level_].key.is_null() || sub_nodes_[level_].key.empty()) {
        curr_.clear();
        skip_state_ = skip_state_ && !first_uncovered_.has_value();
        return {};
    }

    if (consume()) {
        return {curr_, Bytes(hash(sub_nodes_[level_].hash_id)), has_tree()};
    }
    return next_sibling();
}

std::optional<Bytes> AccCursor::first_uncovered_prefix() const {
    if (!first_uncovered_.has_value()) {
        return std::nullopt;
    }
    return pack_nibbles(first_uncovered_.value());
}

ByteView AccCursor::hash(int8_t id) {
    return sub_nodes_[level_].hashes.substr(kHashLength * static_cast<uint16_t>(id), kHashLength);
}
bool AccCursor::has_tree() { return sub_nodes_[level_].has_tree(); }

AccCursor::move_operation_result AccCursor::next_sibling() {
    skip_state_ = skip_state_ && has_tree();
    preorder_traversal_step();

    while (!sub_nodes_[level_].key.empty()) {
        if (consume()) {
            return {curr_, Bytes(hash(sub_nodes_[level_].hash_id)), has_tree()};
        }
        skip_state_ = skip_state_ && has_tree();
        preorder_traversal_step();
    }

    curr_.clear();
    skip_state_ = skip_state_ && !first_uncovered_.has_value();
    return {};
}

void AccCursor::preorder_traversal_step() {
    auto& sub_node{sub_nodes_[level_]};
    if (sub_node.has_tree()) {
        next_.assign(sub_node.key_and_nibble());
        if (db_seek(next_)) {
            return;
        }
    }
    preorder_traversal_step_no_indepth();
}

void AccCursor::preorder_traversal_step_no_indepth() {
    if (next_sibling_in_mem() || next_sibling_of_parent_in_mem()) {
        return;
    }
    next_sibling_in_db();
}

void AccCursor::delete_current() {
    auto& sub_node{sub_nodes_[level_]};
    if (!sub_node.deleted && !sub_node.key.empty()) {
        if (collector_) {
            collector_->collect({Bytes{sub_node.key}, Bytes{}});
        }
        sub_node.deleted = true;
    }
}
void AccCursor::parse_subnode(ByteView key, ByteView value) {
    // Reset all nodes from current level
    // to length of key
    size_t from{level_ + 1};
    size_t to{key.length()};
    if (level_ >= key.length()) {
        from = key.length() + 1;
        to = level_ + 2;
    }
    for (size_t i{from}; i < to; ++i) {
        sub_nodes_[i].reset();
    }

    level_ = key.length();  // We're that deep
    sub_nodes_[level_].parse(key, value);
}

void AccCursor::next_sibling_in_db() {
    auto& sub_node{sub_nodes_[level_]};
    auto incremented_key{increment_nibbled_key(sub_node.key)};
    if (!incremented_key.has_value()) {
        sub_node.key = ByteView();
        return;
    }
    next_.assign(*incremented_key);
    (void)db_seek(next_);
}

bool AccCursor::next_sibling_in_mem() {
    auto& sub_node{sub_nodes_[level_]};
    const int8_t max{static_cast<int8_t>(bitlen_16(sub_node.state_mask))};
    while (sub_node.child_id < max) {
        ++sub_node.child_id;
        if (sub_node.has_hash()) {
            ++sub_node.hash_id;
            return true;
        }
        if (sub_node.has_tree()) {
            return true;
        }
        if (sub_node.has_state()) {
            skip_state_ = false;
        }
    }
    return false;
}

bool AccCursor::next_sibling_of_parent_in_mem() {
    while (level_ > 1) {
        size_t non_null_level{level_ - 1};
        if (sub_nodes_[non_null_level].key.empty()) {
            while (sub_nodes_[non_null_level].key.empty() && non_null_level > 1) {
                --non_null_level;
            }
            next_.assign(sub_nodes_[level_].key_and_nibble());
            buff_.assign(sub_nodes_[non_null_level].key_and_nibble());
            if (db_seek(next_, buff_)) {
                return true;
            }
            level_ = non_null_level + 1;
            continue;
        }
        --level_;
        if (next_sibling_in_mem()) {
            return true;
        }
    }
    return false;
}

bool AccCursor::db_seek(ByteView seek_key, ByteView within_prefix) {
    // Actually db key is prefixed with hashed_account+incarnation for TrieStorage
    // For TrieAccount instead there is no prefix
    Bytes seek_full_key(prefix_.length() + seek_key.length(), '\0');
    std::memcpy(&seek_full_key[0], prefix_.data(), prefix_.length());
    std::memcpy(&seek_full_key[prefix_.length()], seek_key.data(), seek_key.length());

    auto data{seek_full_key.empty() ? db_cursor_.to_first(false)
                                    : db_cursor_.lower_bound(db::to_slice(seek_full_key), false)};

    // Ensure we cover the right prefix (makes sense only for TrieStorage)
    if (data && !prefix_.empty() && !data.key.starts_with(db::to_slice(prefix_))) {
        data.done = false;
    }

    // Ensure we're in the boundaries of requested keys
    auto subnode_key{db::from_slice(data.key)};
    auto subnode_val{db::from_slice(data.value)};
    subnode_key.remove_prefix(prefix_.length());  // Remove db prefix for TrieStorage
    const auto boundary{within_prefix.empty() ? prefix_ : within_prefix};
    if (data && !subnode_key.starts_with(boundary)) {
        data.done = false;
    }

    if (!data) {
        if (within_prefix.empty()) {
            sub_nodes_[level_].key = ByteView();  // It'll terminate the loop
        }
        return false;
    }

    //    // Ensure retrieved data (if any) is within boundaries
    //    if (!within_prefix.empty()) {
    //        if (!data || !db::from_slice(data.key).starts_with(within_prefix)) {
    //            return false;
    //        }
    //    } else {
    //        if (!data || !db::from_slice(data.key).starts_with(prefix_)) {
    //            auto& sub_node{sub_nodes_[level_]};
    //            sub_node.key = ByteView();
    //            return false;
    //        }
    //    }

    try {
        parse_subnode(subnode_key, subnode_val);  // and load data into slot (may throw)
    } catch (const std::exception& ex) {
        // Needed to keep notion of original db key
        std::string what{"Trie key " + to_hex(db::from_slice(data.key), true) + " "};
        what.append(ex.what());
        throw std::invalid_argument(what);
    }

    if (level_) {
        (void)next_sibling_in_mem();
    }
    return true;
}

bool AccCursor::key_is_before(ByteView k1, ByteView k2) {
    if (k1.is_null() || k1.empty()) {
        return false;
    }
    if (k2.is_null() || k2.empty()) {
        return true;
    }
    return k1 < k2;
}

bool AccCursor::consume() {
    auto& sub_node{sub_nodes_[level_]};
    if (sub_node.has_hash()) {
        // Changed list contains the FULL db key
        const auto sub_node_full_key{sub_node.key_and_nibble()};
        buff_.assign(prefix_);
        buff_.append(sub_node_full_key);

        auto [in_changed_list, next_created]{changed_.contains_and_next_marked(buff_)};
        if (!in_changed_list) {
            next_created.remove_prefix(prefix_.length());
            skip_state_ = skip_state_ && key_is_before(sub_node_full_key, next_created_);
            next_created_.assign(next_created);
            curr_.assign(sub_node_full_key);
            return true;
        }
    }
    delete_current();
    return false;
}

Bytes AccCursor::SubNode::key_and_nibble() const {
    Bytes ret{key};
    ret.push_back(static_cast<uint8_t>(child_id));
    return ret;
}

bool AccCursor::SubNode::has_state() const { return ((1 << child_id) & state_mask) != 0; }
bool AccCursor::SubNode::has_tree() const { return ((1 << child_id) & tree_mask) != 0; }
bool AccCursor::SubNode::has_hash() const { return ((1 << child_id) & hash_mask) != 0; }

void AccCursor::SubNode::reset() {
    key = ByteView();
    root_hash = ByteView();
    hashes = ByteView();
    state_mask = 0;
    tree_mask = 0;
    hash_mask = 0;
    hash_id = 0;
    child_id = 0;
    deleted = false;
}

void AccCursor::SubNode::parse(ByteView k, ByteView v) {
    // At least state/tree/hash masks need to be present
    if (v.length() < 6) {
        throw std::invalid_argument("wrong node raw length: expected >= 6 got " + std::to_string(v.length()));
    }
    // Beyond the 6th byte the length must be a multiple of kHashLength
    if ((v.length() - 6) % kHashLength != 0) {
        throw std::invalid_argument("wrong node raw hashes length: not a multiple of " + std::to_string(kHashLength));
    }

    key = k;
    hashes = v.substr(6);
    deleted = false;
    state_mask = endian::load_big_u16(&v[0]);
    tree_mask = endian::load_big_u16(&v[2]);
    hash_mask = endian::load_big_u16(&v[4]);

    if (!is_subset(tree_mask, state_mask)) {
        throw std::invalid_argument("tree mask not subset of state mask");
    }
    if (!is_subset(hash_mask, state_mask)) {
        throw std::invalid_argument("hash mask not subset of state mask");
    }

    auto expected_hashes_count{popcount_16(hash_mask)};
    auto effective_hashes_count{hashes.length() / kHashLength};
    if (effective_hashes_count == (expected_hashes_count + 1)) {
        root_hash = hashes.substr(0, kHashLength);
        hashes.remove_prefix(kHashLength);
    } else {
        root_hash = ByteView();
    }

    hash_id = -1;
    child_id = static_cast<int8_t>(ctz_16(state_mask) - 1);
}

}  // namespace silkworm::trie
