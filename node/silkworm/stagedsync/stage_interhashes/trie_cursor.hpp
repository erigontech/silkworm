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

//! \brief TrieCursor class helps traversing the MerkleTree for Accounts and Storage
//! \details Traversing the trie relies on various assumptions
//! \verbatim
//! 1) The keys being processed represent a node in the trie
//! 2) The keys being processed are served in lexicographical order
//! 3) The keys in database are stored in lexicographical order
//! 4) Whenever a key is found it is checked against a list of changed accounts (or storage locations) to determine
//! whether the retrieved node can be used as is or it needs to be recalculated
//! \endverbatim
//! The implementation takes into account that : TrieAccount hold all the nodes for Hashed accounts (hence is a single
//! tree) whilst TrieStorage hold as many trees as many contracts are active on the chain (hence collection of trees).
//! In this second case each tree is stored with a prefix which is exactly the sum of hashed address + incarnation.
//! Due to the above traversing the trees implies there is no prefix for Accounts whilst there is always a prefix of 40
//! bytes for Storage.

class TrieCursor {
  public:
    explicit TrieCursor(mdbx::cursor& db_cursor, PrefixSet* changed, etl::Collector* collector = nullptr);

    // Not copyable nor movable
    TrieCursor(const TrieCursor&) = delete;
    TrieCursor& operator=(const TrieCursor&) = delete;

    //! \brief Represent the data returned after a move operation (to_prefix or to_next)
    struct move_operation_result {
        bool skip_state{false};             // Whether the node can be used as is without need to recompute root hash
        std::optional<Bytes> key{};         // Nibbled key of node
        std::optional<Bytes> packed_key{};  // Packed key of node
        std::optional<Bytes> hash{};        // Hash of node
        bool children_in_trie{false};       // Whether there are children in trie
    };

    //! \brief Acquires the prefix and position the cursor to the first occurrence
    [[nodiscard]] move_operation_result to_prefix(ByteView prefix);

    //! \brief Moves the cursor to next relevant position
    [[nodiscard]] move_operation_result to_next();

  private:
    struct SubNode {
        Bytes key{};       // Nibbled key value of current subnode
        ByteView value{};  // Value retrieved from db (if any)

        uint16_t state_mask{0};  // One bit set for every child nibbled key state
        uint16_t tree_mask{0};   // One bit set for every child node
        uint16_t hash_mask{0};   // One bit set for every child node hash
        ByteView root_hash{};    // Root Hash
        ByteView hashes{};       // Child nodes hashes

        int8_t child_id{-1};  // Current child being inspected in this node (aka nibble)
        bool deleted{false};  // Whether already deleted (in collector)

        [[nodiscard]] bool has_tree() const;   // Whether current child_id has bit set in tree mask
        [[nodiscard]] bool has_hash() const;   // Whether current child_id has bit set in hash mask
        [[nodiscard]] bool has_state() const;  // Whether current child_id has bit set in state mask

        void reset();                                         // Resets node to default values
        void parse(ByteView k, ByteView v);                   // Parses node data contents from db (may throw)
        [[nodiscard]] Bytes full_key() const;                 // Returns full key to child node (i.e. key + child_id)
        [[nodiscard]] std::optional<Bytes> get_hash() const;  // Returns hash of child node (i.e. key + child_id)
    };

    std::array<SubNode, 64> sub_nodes_{{}};  // Collection of subnodes being unrolled
    uint32_t level_{0};                      // Depth level in sub_nodes_

    Bytes prefix_{};    // Db key prefix for this trie (0 bytes TrieAccount - 40 bytes TrieStorage)
    Bytes buffer_{};    // A convenience buffer

    mdbx::cursor db_cursor_;    // The underlying db cursor (TrieAccount/TrieStorage)
    bool db_cursor_eof_{true};  // Whether there is no more data to read from database
    ByteView db_cursor_key_{};  // Key at current db_cursor position
    ByteView db_cursor_val_{};  // Value at current db_cursor position

    PrefixSet* changed_;         // The collection of changed nibbled keys
    etl::Collector* collector_;  // Pointer to a collector for deletion of obsolete keys

    void db_seek(ByteView seek_key);  // Seeks lowerbound of provided key using db_cursor_

    void collect_deletion(SubNode& sub_node);  // Collects deletion of sub-node being rebuilt or no longer needed
};

}  // namespace silkworm::trie

#endif  // SILKWORM_STAGEDSYNC_STAGE_INTERHASHES_CURSOR_HPP_
