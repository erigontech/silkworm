// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>

#include <silkworm/core/trie/node.hpp>
#include <silkworm/core/trie/prefix_set.hpp>
#include <silkworm/db/datastore/etl/collector.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>

namespace silkworm::trie {

//! \brief Extends trie::Node with methods for traversing child_ids
class SubNode : public Node {
  public:
    SubNode() = default;

    // Not copyable nor movable
    SubNode(const SubNode&) = delete;
    SubNode& operator=(const SubNode&) = delete;

    bool has_tree() const noexcept;   // Whether current child_id has bit set in tree mask
    bool has_hash() const noexcept;   // Whether current child_id has bit set in hash mask
    bool has_state() const noexcept;  // Whether current child_id has bit set in state mask

    void reset();                        // Resets node to default values
    void parse(ByteView k, ByteView v);  // Parses node data contents from db (may throw)
    Bytes full_key() const noexcept;     // Returns full key to child node (i.e. key + child_id)
    const evmc::bytes32& hash();         // Returns hash of child node (i.e. key + child_id)

    ByteView key{};            // Key retrieved from db (if any) Is nibbled
    ByteView value{};          // Value retrieved from db (if any)
    int8_t child_id{-1};       // Current child being inspected in this node (aka nibble)
    int8_t max_child_id{0xf};  // Max child of this node
    int8_t hash_id{-1};        // Index of hash to be retrieved
    bool deleted{false};       // Whether already deleted (in collector)
};

//! \brief Traverses TrieAccount or TrieStorage in pre-order: \n
//! 1. Visit the current node \n
//! 2. Recursively traverse the current node's left subtree. \n
//! 3. Recursively traverse the current node's right subtree. \n
//! \see https://en.wikipedia.org/wiki/Tree_traversal#Pre-order,_NLR
//! \see Erigon's AccTrieCursor/StorageTrieCursor
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
    explicit TrieCursor(
        datastore::kvdb::ROCursor& db_cursor,
        PrefixSet* changed,
        datastore::etl::Collector* collector = nullptr);

    // Not copyable nor movable
    TrieCursor(const TrieCursor&) = delete;
    TrieCursor& operator=(const TrieCursor&) = delete;

    //! \brief Represent the data returned after a move operation (to_prefix or to_next)
    struct [[nodiscard]] MoveOperationResult {
        std::optional<Bytes> key{};              // Nibbled key of node
        std::optional<evmc::bytes32> hash{};     // Hash of node
        bool children_in_trie{false};            // Whether there are children in trie
        std::optional<Bytes> first_uncovered{};  // First uncovered prefix to be processed by higher loop
    };

    //! \brief Acquires the prefix and position the cursor to the first occurrence
    MoveOperationResult to_prefix(ByteView prefix);

    //! \brief Moves the cursor to next relevant position
    MoveOperationResult to_next();

  private:
    uint32_t level_{0};                      // Depth level in sub_nodes_
    bool end_of_tree_{false};                // Protects from to_next() beyond end of tree
    Bytes curr_key_{};                       // Latest key returned on a valid hash
    Bytes prev_key_{};                       // Same as curr_key_ but for previous cycle
    bool skip_state_{true};                  // Whether account(s) state scan can be skipped
    std::array<SubNode, 32> sub_nodes_{{}};  // Collection of sub-nodes being unrolled

    Bytes prefix_{};  // Db key prefix for this trie (0 bytes TrieAccount - 40 bytes TrieStorage)
    Bytes buffer_{};  // A convenience buffer

    datastore::kvdb::ROCursor& db_cursor_;  // The underlying db cursor (TrieAccount/TrieStorage)
    PrefixSet* changed_list_;               // The collection of changed nibbled keys
    ByteView next_created_{};               // The next created account/location in changed list
    datastore::etl::Collector* collector_;  // Pointer to a collector for deletion of obsolete keys

    bool db_seek(ByteView seek_key);  // Seeks lowerbound of provided key using db_cursor_
    void db_delete(SubNode& node);    // Collects deletion of node being rebuilt or no longer needed
    bool consume(SubNode& node);      // If node has hash consume it

    //! \brief Returns the first uncovered prefix. nullopt if overflows
    //! \see increment_nibbled_key()
    std::optional<Bytes> first_uncovered();

  public:
    //! \brief Produces the next key in sequence
    //! \details It's essentially +1 in the hexadecimal (base 16) numeral system
    //! \verbatim
    //! Example :
    //! increment_nibbled_key(0x125) == 0x126;
    //! increment_nibbled_key(0x12f) == 0x13; (note is shorter)
    //! increment_nibbled_key(0x13) == 0x14;
    //! \endverbatim
    //! \returns the new string of bytes or nullopt if overflows
    static std::optional<Bytes> increment_nibbled_key(ByteView origin);

    //! \brief Compares two strings and returns true when k1 < k2
    //! \remarks Unlike standard lexical comparison null keys are last
    static bool key_is_before(ByteView k1, ByteView k2);
};

}  // namespace silkworm::trie
