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
            if (!has_prefix(key, prefix_)) {
                subnodes_.clear();
                return;
            }
            key.remove_prefix(prefix_.length());
        }
    }

    std::optional<Node> node{std::nullopt};
    int nibble{0};
    if (db_data) {
        node = Node::from_encoded_storage(db::from_slice(db_data.value));
        SILKWORM_ASSERT(node.has_value());
        SILKWORM_ASSERT(node->state_mask() != 0);
        nibble = node->root_hash().has_value() ? -1 : ctz_16(node->state_mask()) - 1;
    } else {
        nibble = -1;
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

    const auto& sub_node{subnodes_.back()};
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

        while (sub_node.nibble <= 0xF) {
            if (sub_node.node->state_mask() & (1u << sub_node.nibble)) {
                return;
            }
            ++sub_node.nibble;
        }

        // this node is fully traversed
        subnodes_.pop_back();
        allow_root_to_child_nibble_within_subnode = false;
    }
}

Bytes Cursor::SubNode::full_key() const {
    Bytes out{key};
    if (nibble >= 0) {
        out.push_back(nibble);
    }
    return out;
}

bool Cursor::SubNode::state_flag() const {
    if (nibble < 0 || !node.has_value()) {
        return true;
    }
    return node->state_mask() & (1u << nibble);
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

AccCursor::move_operation_result AccCursor::at_prefix(ByteView prefix) {
    skip_state_ = true;
    prefix_.assign(prefix);

    auto [_, next_created]{changed_.contains_and_next_marked({})};
    next_created_ = next_created;
    prev_.assign(curr_);

    if (!seek_in_db(prefix, {})) {
        curr_.clear();
        skip_state_ = false;
        return {};
    }
    if (consume()) {
        return {{curr_}, hash(sub_nodes_[level_].hash_id), has_tree()};
    }
    return next();
}

AccCursor::move_operation_result AccCursor::to_next() {
    skip_state_ = true;
    prev_.assign(curr_);
    preorder_traversal_step_no_indepth();

    if (sub_nodes_[level_].key.empty()) {
        curr_.clear();
        skip_state_ = skip_state_ && !increment_nibbled_key(prev_).has_value();
        return {};
    }

    if (consume()) {
        return {{curr_}, hash(sub_nodes_[level_].hash_id), has_tree()};
    }
    return next();
}

std::optional<Bytes> AccCursor::first_uncovered_prefix() const {
    std::optional<Bytes> ret;
    if (!prev_.empty()) {
        ret = increment_nibbled_key(prev_);
    } else {
        ret.emplace(prefix_);
    }

    if (!ret.has_value()) {
        return ret;
    }
    return pack_nibbles(ret.value());
}

ByteView AccCursor::hash(int8_t id) {
    return sub_nodes_[level_].value.substr(kHashLength * static_cast<int>(id), kHashLength);
}
bool AccCursor::has_state() { return sub_nodes_[level_].has_state(); }
bool AccCursor::has_tree() { return sub_nodes_[level_].has_tree(); }
bool AccCursor::has_hash() { return sub_nodes_[level_].has_hash(); }

AccCursor::move_operation_result AccCursor::next() {
    skip_state_ = skip_state_ && has_tree();
    preorder_traversal_step();

    while (!sub_nodes_[level_].key.empty()) {
        if (consume()) {
            return {{curr_}, hash(sub_nodes_[level_].hash_id), has_tree()};
        }
        skip_state_ = skip_state_ && has_tree();
        preorder_traversal_step();
    }

    curr_.clear();
    skip_state_ = skip_state_ && !increment_nibbled_key(prev_).has_value();
    return {};
}

void AccCursor::preorder_traversal_step() {
    auto& sub_node{sub_nodes_[level_]};
    if (sub_node.has_tree()) {
        next_.assign(sub_node.key);
        next_.append({static_cast<uint8_t>(sub_node.child_id)});
        if (seek_in_db(next_)) {
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
    // At least state/tree/hash masks need to be present
    if (value.length() < 6) {
        throw std::invalid_argument("Wrong node raw length: expected >= 6 got " + std::to_string(value.length()));
    }
    // Beyond the 6th byte the length must be a multiple of kHashLength
    if ((value.length() - 6) % kHashLength != 0) {
        throw std::invalid_argument("Wrong node raw hashes length: not a multiple of " + std::to_string(kHashLength));
    }

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

    level_ = key.length();
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
    (void)seek_in_db(next_, {});
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
            next_.assign(sub_nodes_[level_].key);
            next_.append({static_cast<uint8_t>(sub_nodes_[level_].child_id)});
            buff_.assign(sub_nodes_[non_null_level].key);
            buff_.append({static_cast<uint8_t>(sub_nodes_[non_null_level].child_id)});
            if (seek_in_db(next_, buff_)) {
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

bool AccCursor::seek_in_db(ByteView key, ByteView within_prefix) {
    const auto data{next_.empty() ? db_cursor_.to_first(false) : db_cursor_.lower_bound(db::to_slice(key), false)};
    if (!within_prefix.empty()) {
        if (!data || !has_prefix(db::from_slice(data.key), within_prefix)) {
            return false;
        }
    } else {
        if (!data || !has_prefix(db::from_slice(data.key), prefix_)) {
            auto& sub_node{sub_nodes_[level_]};
            sub_node.key = ByteView();
            sub_node.value = ByteView();
            return false;
        }
    }
    parse_subnode(db::from_slice(data.key), db::from_slice(data.value));
    (void)next_sibling_in_mem();
    return true;
}

bool AccCursor::consume() {
    auto& sub_node{sub_nodes_[level_]};
    if (sub_node.has_hash()) {
        buff_.assign(sub_node.key);
        buff_.append({static_cast<uint8_t>(sub_node.child_id)});
        auto [in_changed_list, next_created]{changed_.contains_and_next_marked(buff_)};
        if (!in_changed_list) {
            skip_state_ = skip_state_ && key_is_before(buff_, next_created_);
            next_created_.assign(next_created);
            curr_.assign(buff_);
            return true;
        }
    }
    delete_current();
    return false;
}

bool key_is_before(ByteView k1, ByteView k2) {
    if (k1.empty()) {
        return false;
    }
    if (k2.empty()) {
        return true;
    }
    return k1 < k2;
}

bool AccCursor::SubNode::has_state() const { return ((1 << child_id) & state_mask) != 0; }
bool AccCursor::SubNode::has_tree() const { return ((1 << child_id) & tree_mask) != 0; }
bool AccCursor::SubNode::has_hash() const { return ((1 << child_id) & hash_mask) != 0; }

void AccCursor::SubNode::reset() {
    key = ByteView();
    value = ByteView();
    state_mask = 0;
    tree_mask = 0;
    hash_mask = 0;
    hash_id = 0;
    child_id = 0;
    deleted = false;
}

void AccCursor::SubNode::parse(ByteView k, ByteView v) {
    key = k;
    value = v.substr(6);
    deleted = false;
    state_mask = endian::load_big_u16(&v[0]);
    tree_mask = endian::load_big_u16(&v[2]);
    hash_mask = endian::load_big_u16(&v[4]);
    hash_id = -1;
    child_id = static_cast<int8_t>(ctz_16(state_mask) - 1);
}

}  // namespace silkworm::trie
