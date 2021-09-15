/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_TRIE_INTERMEDIATE_HASHES_HPP_
#define SILKWORM_TRIE_INTERMEDIATE_HASHES_HPP_

/* On TrieAccount & TrieStorage DB tables

state_mask - mark prefixes existing in HashedAccount (HashedStorage) table
tree_mask - mark prefixes existing in TrieAccount (TrieStorage) table
hash_mask - mark prefixes whose hashes are saved in the current TrieAccount (TrieStorage) record (actually only
hashes of branch nodes can be saved)

For example:
+----------------------------------------------------------------------------------------------------+
| DB record: 0xB, state_mask: 0b1011, tree_mask: 0b0001, hash_mask: 0b1001, hashes: [x,x]            |
+----------------------------------------------------------------------------------------------------+
                |                                           |                               |
                v                                           |                               v
+-----------------------------------------------+           |               +----------------------------------------+
| DB record: 0xB0, state_mask: 0b10001          |           |               | BranchNode: 0xB3                       |
| tree_mask: 0, hash_mask: 0b10000, hashes: [x] |           |               | has no record in TrieAccount           |
+-----------------------------------------------+           |               +----------------------------------------+
        |                    |                              |                         |                  |
        v                    v                              v                         v                  v
+--------------------+   +----------------------+     +---------------+        +---------------+  +---------------+
| Account:           |   | BranchNode: 0xB04    |     | Account:      |        | Account:      |  | Account:      |
| 0xB00...           |   | has no record in     |     | 0xB1...       |        | 0xB31...      |  | 0xB34...      |
| in HashedAccount   |   |    TrieAccount       |     |               |        |               |  |               |
+--------------------+   +----------------------+     +---------------+        +---------------+  +---------------+
                           |                |
                           v                v
                      +---------------+  +---------------+
                      | Account:      |  | Account:      |
                      | 0xB040...     |  | 0xB041...     |
                      +---------------+  +---------------+
N.B. Nibbles in TrieAccount keys are actually unpacked (one nibble per byte unlike shown above),
while keys in HashedAccount are packed (two nibbles per byte).

Invariants:
- tree_mask is a subset of state_mask (tree_mask ⊆ state_mask)
- hash_mask is a subset of state_mask (hash_mask ⊆ state_mask)
- the first level in TrieAccount always exists if state_mask≠0
- TrieStorage record of account root (length=40) must have +1 hash - it's the account root
- each record in TrieAccount table must have an ancestor (may be not immediate) and this ancestor must have
the correct bit in tree_mask bitmap
- if state_mask has a bit - then HashedAccount table must have a record corresponding to this bit
- each TrieAccount record must cover some state (means state_mask is always ≠ 0)
- TrieAccount records with length=1 may satisfy (tree_mask=0 ∧ hash_mask=0)
- Other records in TrieAccount and TrieStorage must satisfy (tree_mask≠0 ∨ hash_mask≠0)
*/

#include <optional>
#include <vector>

#include <silkworm/common/base.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/trie/hash_builder.hpp>
#include <silkworm/trie/prefix_set.hpp>
#include <silkworm/types/account.hpp>

namespace silkworm::trie {

// Erigon AccTrieCursor
class AccountTrieCursor {
  public:
    AccountTrieCursor(const AccountTrieCursor&) = delete;
    AccountTrieCursor& operator=(const AccountTrieCursor&) = delete;

    AccountTrieCursor(mdbx::txn& txn, const PrefixSet& changed);

    void next(bool skip_children);

    // nullopt key signifies trie's end
    std::optional<Bytes> key() const;

    const evmc::bytes32* hash() const;

    bool can_skip_state() const;

  private:
    void seek_node(ByteView lower_bound);

    const PrefixSet& changed_;
    bool at_root_{true};
    mdbx::cursor_managed cursor_;
    uint8_t nibble_{0};
    std::optional<Node> node_{std::nullopt};
};

// Erigon StorageTrieCursor
class StorageTrieCursor {
  public:
    StorageTrieCursor(const StorageTrieCursor&) = delete;
    StorageTrieCursor& operator=(const StorageTrieCursor&) = delete;

    explicit StorageTrieCursor(mdbx::txn& txn);

    Bytes seek_to_account(ByteView hashed_address_with_incarnation);

    Bytes first_uncovered_prefix();

    std::optional<Bytes> key() const;

    void next();

    bool can_skip_state() const;
};

// Erigon FlatDBTrieLoader
class DbTrieLoader {
  public:
    DbTrieLoader(const DbTrieLoader&) = delete;
    DbTrieLoader& operator=(const DbTrieLoader&) = delete;

    DbTrieLoader(mdbx::txn& txn, etl::Collector& account_collector, etl::Collector& storage_collector);

    evmc::bytes32 calculate_root(const PrefixSet& changed);

  private:
    mdbx::txn& txn_;
    HashBuilder hb_;
    etl::Collector& storage_collector_;
    Bytes rlp_;
};

class WrongRoot : public std::runtime_error {
  public:
    WrongRoot() : std::runtime_error{"wrong trie root"} {}
};

// Erigon RegenerateIntermediateHashes
// might throw WrongRoot
// returns the state root
evmc::bytes32 regenerate_intermediate_hashes(mdbx::txn& txn, const char* etl_dir,
                                             const evmc::bytes32* expected_root = nullptr);

// Erigon incrementIntermediateHashes
// might throw WrongRoot
// returns the state root
evmc::bytes32 increment_intermediate_hashes(mdbx::txn& txn, const char* etl_dir, BlockNum from,
                                            const evmc::bytes32* expected_root = nullptr);

}  // namespace silkworm::trie

#endif  // SILKWORM_TRIE_INTERMEDIATE_HASHES_HPP_
