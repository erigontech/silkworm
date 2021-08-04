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

/* On trie_account & trie_storage DB tables

state_mask - mark prefixes existing in hashed_accounts (hashed_storage) table
tree_mask - mark prefixes existing in trie_account (trie_storage) table
hash_mask - mark prefixes whose hashes are saved in the current trie_account (trie_storage) record (actually only
hashes of branch nodes can be saved)

For example:
+-----------------------------------------------------------------------------------------------------+
| DB record: 0x0B, state_mask: 0b1011, tree_mask: 0b1001, hash_mask: 0b1001, hashes: [x,x]            |
+-----------------------------------------------------------------------------------------------------+
                |                                           |                               |
                v                                           |                               v
+-----------------------------------------------+           |            +----------------------------------------+
| DB record: 0x0B00, state_mask: 0b10001        |           |            | DB record: 0x0B03, state_mask: 0b10010 |
| tree_mask: 0, hash_mask: 0b10000, hashes: [x] |           |            | tree_mask: 0, hash_mask: 0, hashes: [] |
+-----------------------------------------------+           |            +----------------------------------------+
        |                    |                              |                         |                  |
        v                    v                              v                         v                  v
+--------------------+   +----------------------+     +---------------+        +---------------+  +---------------+
| Account:           |   | BranchNode: 0x0B0004 |     | Account:      |        | Account:      |  | Account:      |
| 0xB00...           |   | has no record in     |     | 0xB1...       |        | 0xB31...      |  | 0xB34...      |
| in hashed_accounts |   |    trie_account      |     |               |        |               |  |               |
+--------------------+   +----------------------+     +---------------+        +---------------+  +---------------+
                           |                |
                           v                v
                      +---------------+  +---------------+
                      | Account:      |  | Account:      |
                      | 0xB040...     |  | 0xB041...     |
                      +---------------+  +---------------+
N.B. Nibbles in trie_account keys are unpacked, while hashed_accounts have packed keys.

Invariants:
- tree_mask is a subset of state_mask (tree_mask ⊆ state_mask)
- hash_mask is a subset of state_mask (hash_mask ⊆ state_mask)
- the first level in account_trie always exists if state_mask≠0
- trie_storage record of account root (length=40) must have +1 hash - it's the account root
- each record in trie_account table must have an ancestor (may be not immediate) and this ancestor must have
the correct bit in tree_mask bitmap
- if state_mask has a bit - then hashed_accounts table must have a record corresponding to this bit
- each trie_account record must cover some state (means state_mask is always ≠ 0)
- trie_account records with length=1 may satisfy (tree_mask=0 ∧ hash_mask=0)
- Other records in trie_account and trie_storage must satisfy (tree_mask≠0 ∨ hash_mask≠0)
*/

#include <optional>
#include <vector>

#include <silkworm/common/base.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/trie/hash_builder.hpp>
#include <silkworm/types/account.hpp>

namespace silkworm::trie {

// Erigon AccTrieCursor
class AccountTrieCursor {
  public:
    AccountTrieCursor(const AccountTrieCursor&) = delete;
    AccountTrieCursor& operator=(const AccountTrieCursor&) = delete;

    explicit AccountTrieCursor(mdbx::txn& txn);

    Bytes first_uncovered_prefix();

    std::optional<Bytes> key() const;

    void next();

    bool can_skip_state() const;
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

    evmc::bytes32 calculate_root();

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

// Erigon MarshalTrieNode
Bytes marshal_node(const Node& n);

// Erigon UnmarshalTrieNode
Node unmarshal_node(ByteView v);

// Erigon RegenerateIntermediateHashes
// might throw WrongRoot
// returns the state root
evmc::bytes32 regenerate_intermediate_hashes(mdbx::txn& txn, const char* etl_dir,
                                             const evmc::bytes32* expected_root = nullptr);

}  // namespace silkworm::trie

#endif  // SILKWORM_TRIE_INTERMEDIATE_HASHES_HPP_
