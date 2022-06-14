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

#ifndef SILKWORM_STAGEDSYNC_STAGE_INTERHASHES_CURSOR_HPP_
#define SILKWORM_STAGEDSYNC_STAGE_INTERHASHES_CURSOR_HPP_

#include <silkworm/db/mdbx.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/trie/node.hpp>
#include <silkworm/trie/prefix_set.hpp>

namespace silkworm::trie {

//! \brief Traverses TrieAccount or TrieStorage in pre-order: \n
//! 1. Visit the current node \n
//! 2. Recursively traverse the current node's left subtree. \n
//! 3. Recursively traverse the current node's right subtree. \n
//! \see https://en.wikipedia.org/wiki/Tree_traversal#Pre-order,_NLR
//! \see Erigon's AccTrieCursor/StorageTrieCursor

class Cursor {
  public:
    // Ignores DB entries whose keys don't start with the prefix
    explicit Cursor(mdbx::cursor& db_cursor, PrefixSet& changed, etl::Collector* collector, ByteView prefix = {});

    // Not copyable nor movable
    Cursor(const Cursor&) = delete;
    Cursor& operator=(const Cursor&) = delete;

    void next();                                     // Moves to next sibling of current node: child or parent
    [[nodiscard]] std::optional<Bytes> key() const;  // nullopt key signifies end-of-tree
    [[nodiscard]] const evmc::bytes32* hash() const;
    [[nodiscard]] bool children_are_in_trie() const;
    [[nodiscard]] bool can_skip_state() const { return can_skip_state_; }
    [[nodiscard]] std::optional<Bytes> first_uncovered_prefix() const;
    [[nodiscard]] size_t level() const { return subnodes_.size(); }

  private:
    // TrieAccount(TrieStorage) node with a particular nibble selected
    struct SubNode {
        Bytes key;
        std::optional<Node> node;
        int nibble{-1};  // -1 points to the node itself instead of a nibble

        [[nodiscard]] Bytes full_key() const;
        [[nodiscard]] bool tree_flag() const;
        [[nodiscard]] bool hash_flag() const;
        [[nodiscard]] const evmc::bytes32* hash() const;
    };

    void consume_node(ByteView key, bool exact);
    void move_to_next_sibling(bool allow_root_to_child_nibble_within_subnode);
    void update_skip_state();

    mdbx::cursor db_cursor_;         // Cursor to trie table
    PrefixSet& changed_;             // Holds the list of touched addresses for which nodes can not be skipped
    etl::Collector* collector_;      // To queue deleted records and postpone deletion
    Bytes prefix_;                   // Actual prefix of this trie.
    std::vector<SubNode> subnodes_;  // Sub-nodes being traversed
    bool can_skip_state_{false};     // Whether or not actual node can be accepted by HashBuilder as is

};

//! \brief Produces the next key in sequence from provided nibbled key
//! \details It's essentially +1 in the hexadecimal (base 16) numeral system.
//! \example
//! \verbatim
//! increment_key(120) = 121
//! increment_key(12e) = 12f
//! increment_key(12f) = 13
//! \endverbatim
//! \return The incremented (and eventually shortened) sequence of 0xF nibbles,
//! \remarks Being a prefix of nibbles trailing zeroes must be erased
std::optional<Bytes> increment_nibbled_key(ByteView nibbles);

}  // namespace silkworm::trie

#endif  // SILKWORM_STAGEDSYNC_STAGE_INTERHASHES_CURSOR_HPP_
