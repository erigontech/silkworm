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

class AccCursor {
  public:
    explicit AccCursor(mdbx::cursor& db_cursor, PrefixSet& changed, etl::Collector* collector = nullptr);

    struct move_operation_result {
        std::optional<Bytes> key{};   // The nibbled key of node being processed
        std::optional<Bytes> hash{};  // The hash of node being processed
        bool has_tree{false};         // Whether this node has children
    };

    //! \brief Sets the trie cursor to given prefix
    //! \details Tries are separated into TrieAccounts and TrieStorage. TrieAccounts stores all nodes needed to build
    //! the StateRoot whilst TrieStorage holds every node needed to build Storage Root for every contract account. By
    //! consequence TrieAccounts has keys which are always made of only nibbled keys whilst TrieStorage has all nibbled
    //! keys owned by storage root prefixed by the contract address hash + its incarnation. Due to this brief
    //! explanation this method makes sense only once (with empty prefix) for TrieAccounts and traverse the whole tree
    //! whilst for TrieStorage it must be used to set the account + incarnation for which we want to traverse the trie
    //! and build StorageRoot
    move_operation_result to_prefix(ByteView prefix);  // See Erigon's AtPrefix

    //! \brief Advances the cursor to next position (child or child-of-parent) and computes whether or not
    //! discovered (or computed) node has to be up-serted in the trie
    move_operation_result to_next();  // See Erigon's Next (capital N)

    //! \brief Returns the first nibbled prefix higher code must process to upsert this node in the trie
    std::optional<Bytes> first_uncovered_prefix() const;  // Next prefix (packed) not covered in subtree

    //! \brief Returns whether the discovered node can be used as-is without recalculation
    [[nodiscard]] bool can_skip_state() const { return skip_state_; }

  private:
    struct SubNode {
        ByteView key{};  // Current nibbled key

        uint16_t state_mask{0};  // One bit set for every child nibbled key state
        uint16_t tree_mask{0};   // One bit set for every child node
        uint16_t hash_mask{0};   // One bit set for every child node hash
        ByteView root_hash{};    // Root Hash
        ByteView hashes{};       // Child nodes hashes

        int8_t child_id{0};   // Current child being inspected in this node (aka nibble)
        int8_t hash_id{0};    // Hash to be retrieved
        bool deleted{false};  // Whether already deleted (in collector)

        [[nodiscard]] bool has_state() const;  // Whether current child_id has bit set in state mask
        [[nodiscard]] bool has_tree() const;   // Whether current child_id has bit set in tree mask
        [[nodiscard]] bool has_hash() const;   // Whether current child_id has bit set in hash mask

        void reset();                         // Resets node to default values
        void parse(ByteView k, ByteView v);   // Parses node data contents from db (may throw)
        void assign_full_key(Bytes& buffer);  // Returns full key to node (i.e. key + child_id)
    };

    mdbx::cursor& db_cursor_;             // MDBX Cursor to TrieAccounts
    PrefixSet& changed_;                  // List of changed addresses for incremental promotion
    etl::Collector* collector_{nullptr};  // To queue deleted records

    std::array<SubNode, 64> sub_nodes_{{}};
    // std::vector<SubNode> sub_nodes_{64, SubNode{}};
    bool skip_state_{false};
    size_t level_{0};

    Bytes prefix_{};  // global prefix - cursor will never return keys without this prefix
    Bytes prev_{};    // Previous nibbled key
    Bytes curr_{};    // Current nibbled key
    Bytes next_{};    // Next nibbled key
    Bytes buff_{};    // Convenience buffer

    Bytes next_created_{};
    std::optional<Bytes> first_uncovered_{};

    ByteView hash(int8_t id);

    bool has_tree();
    bool key_is_before(ByteView k1, ByteView k2);

    void preorder_traversal_step();
    void preorder_traversal_step_no_indepth();
    void delete_current();

    //! \brief Partially parses node
    //! \remarks We don't need to copy all hashes for trie::Node
    //! \see Erigon's _unmarshal
    void parse_subnode(ByteView key, ByteView value);

    /*
     * Trie traversing
     */

    move_operation_result next_sibling();
    void next_sibling_in_db();
    bool next_sibling_in_mem();
    bool next_sibling_of_parent_in_mem();

    bool db_seek(ByteView seek_key, ByteView within_prefix = {});  // Locates node in db (if any)
    bool consume();  // Marks this node for deletion in collector as will be rebuilt
};

}  // namespace silkworm::trie

#endif  // SILKWORM_STAGEDSYNC_STAGE_INTERHASHES_CURSOR_HPP_
