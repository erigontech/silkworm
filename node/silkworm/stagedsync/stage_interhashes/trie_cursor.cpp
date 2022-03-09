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

#include <silkworm/common/assert.hpp>
#include <silkworm/trie/hash_builder.hpp>

namespace silkworm::trie {

Cursor::Cursor(mdbx::cursor& cursor, PrefixSet& changed, ByteView prefix)
    : cursor_{cursor}, changed_{changed}, prefix_{prefix} {
    consume_node(/*key=*/{}, /*exact=*/true);
}

void Cursor::consume_node(ByteView to, bool exact) {
    const Bytes db_key{prefix_ + Bytes{to}};
    const auto entry{exact ? cursor_.find(db::to_slice(db_key), /*throw_notfound=*/false)
                           : cursor_.lower_bound(db::to_slice(db_key), /*throw_notfound=*/false)};

    if (!entry && !exact) {
        // end-of-tree
        stack_.clear();
        return;
    }

    ByteView key = to;
    if (!exact) {
        key = db::from_slice(entry.key);
        if (!has_prefix(key, prefix_)) {
            stack_.clear();
            return;
        }
        key.remove_prefix(prefix_.length());
    }

    std::optional<Node> node{std::nullopt};
    if (entry) {
        node = unmarshal_node(db::from_slice(entry.value));
        SILKWORM_ASSERT(node.has_value());
        SILKWORM_ASSERT(node->state_mask() != 0);
    }

    int nibble{0};
    if (!node.has_value() || node->root_hash().has_value()) {
        nibble = -1;
    } else {
        while ((node->state_mask() & (1u << nibble)) == 0) {
            ++nibble;
        }
    }

    if (!key.empty() && !stack_.empty()) {
        // the root might have nullopt node and thus no state bits, so we rely on the DB
        stack_[0].nibble = key[0];
    }

    stack_.push_back(SubNode{Bytes{key}, node, nibble});

    update_skip_state();

    // don't erase nodes with valid root hashes
    if (entry && (!can_skip_state_ || nibble != -1)) {
        cursor_.erase();
    }
}

void Cursor::next() {
    if (stack_.empty()) {
        // end-of-tree
        return;
    }

    if (!can_skip_state_ && children_are_in_trie()) {
        // go to the child node
        SubNode& sn{stack_.back()};
        if (sn.nibble < 0) {
            move_to_next_sibling(/*allow_root_to_child_nibble_within_subnode=*/true);
        } else {
            consume_node(*key(), /*exact=*/false);
        }
    } else {
        move_to_next_sibling(/*allow_root_to_child_nibble_within_subnode=*/false);
    }

    update_skip_state();
}

void Cursor::update_skip_state() {
    const std::optional<Bytes> k{key()};
    if (k == std::nullopt || changed_.contains(prefix_ + *k)) {
        can_skip_state_ = false;
    } else {
        can_skip_state_ = stack_.back().hash_flag();
    }
}

void Cursor::move_to_next_sibling(bool allow_root_to_child_nibble_within_subnode) {
    if (stack_.empty()) {
        // end-of-tree
        return;
    }

    SubNode& sn{stack_.back()};

    if (sn.nibble >= 15 || (sn.nibble < 0 && !allow_root_to_child_nibble_within_subnode)) {
        // this node is fully traversed
        stack_.pop_back();
        move_to_next_sibling(false);  // on parent
        return;
    }

    ++sn.nibble;

    if (!sn.node.has_value()) {
        // we can't rely on the state flag, so search in the DB
        consume_node(*key(), /*exact=*/false);
        return;
    }

    for (; sn.nibble < 16; ++sn.nibble) {
        if (sn.state_flag()) {
            return;
        }
    }

    // this node is fully traversed
    stack_.pop_back();
    move_to_next_sibling(false);  // on parent
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
    } else if (nibble < 0) {
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
    const size_t hash_idx{std::bitset<16>(node->hash_mask() & first_nibbles_mask).count()};
    return &node->hashes()[hash_idx];
}

std::optional<Bytes> Cursor::key() const {
    if (stack_.empty()) {
        return std::nullopt;
    }
    return stack_.back().full_key();
}

const evmc::bytes32* Cursor::hash() const {
    if (stack_.empty()) {
        return nullptr;
    }
    return stack_.back().hash();
}

bool Cursor::children_are_in_trie() const {
    if (stack_.empty()) {
        return false;
    }
    return stack_.back().tree_flag();
}

std::optional<Bytes> increment_key(ByteView unpacked) {
    Bytes out{unpacked};
    for (size_t i{out.size()}; i > 0; --i) {
        uint8_t& nibble{out[i - 1]};
        SILKWORM_ASSERT(nibble < 0x10);
        if (nibble < 0xF) {
            ++nibble;
            return out;
        } else {
            nibble = 0;
            // carry over
        }
    }
    return std::nullopt;
}

std::optional<Bytes> Cursor::first_uncovered_prefix() const {
    std::optional<Bytes> k{key()};
    if (can_skip_state_ && k != std::nullopt) {
        k = increment_key(*k);
    }
    if (k == std::nullopt) {
        return std::nullopt;
    }
    return pack_nibbles(*k);
}

}  // namespace silkworm::trie
