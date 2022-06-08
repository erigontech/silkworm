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

bool key_is_before(ByteView k1, ByteView k2) {
    if (k1.empty()) {
        return false;
    }
    if (k2.empty()) {
        return true;
    }
    return k1 < k2;
}

}  // namespace silkworm::trie
