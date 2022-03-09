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

#include "trie_loader.hpp"

#include <silkworm/common/assert.hpp>
#include <silkworm/common/rlp_err.hpp>
#include <silkworm/stagedsync/stage_interhashes/trie_cursor.hpp>
#include <silkworm/types/account.hpp>

namespace silkworm::trie {
DbTrieLoader::DbTrieLoader(mdbx::txn& txn, etl::Collector& account_collector, etl::Collector& storage_collector)
    : txn_{txn}, storage_collector_{storage_collector} {
    hb_.node_collector = [&account_collector](ByteView unpacked_key, const Node& node) {
        if (unpacked_key.empty()) {
            return;
        }

        etl::Entry e;
        e.key = unpacked_key;
        e.value = marshal_node(node);

        account_collector.collect(std::move(e));
    };
}

/*
**Theoretically:** "Merkle trie root calculation" starts from state, build from state keys - trie,
on each level of trie calculates intermediate hash of underlying data.

**Practically:** It can be implemented as "Preorder trie traversal" (Preorder - visit Root, visit Left, visit Right).
But, let's make couple observations to make traversal over huge state efficient.

**Observation 1:** `TrieOfAccounts` already stores state keys in sorted way.
Iteration over this bucket will retrieve keys in same order as "Preorder trie traversal".

**Observation 2:** each Eth block - changes not big part of state - it means most of Merkle trie intermediate hashes
will not change. It means we effectively can cache them. `TrieOfAccounts` stores "Intermediate hashes of all Merkle trie
levels". It also sorted and Iteration over `TrieOfAccounts` will retrieve keys in same order as "Preorder trie
traversal".

**Implementation:** by opening 1 Cursor on state and 1 more Cursor on intermediate hashes bucket - we will receive data
in order of "Preorder trie traversal". Cursors will only do "sequential reads" and "jumps forward" - been
hardware-friendly.

Imagine that account with key 0000....00 (64 zeroes, 32 bytes of zeroes) changed.
Here is an example sequence which can be seen by running 2 Cursors:
```
00                   // key came from cache, can't use it - because account with this prefix changed
0000                 // key came from cache, can't use it - because account with this prefix changed
...
{30 zero bytes}00    // key which came from cache, can't use it - because account with this prefix changed
{30 zero bytes}0000  // account came from state, use it - calculate hash, jump to next sub-trie
{30 zero bytes}01    // key came from cache, it's next sub-trie, use it, jump to next sub-trie
{30 zero bytes}02    // key came from cache, it's next sub-trie, use it, jump to next sub-trie
...
{30 zero bytes}ff    // key came from cache, it's next sub-trie, use it, jump to next sub-trie
{29 zero bytes}01    // key came from cache, it's next sub-trie (1 byte shorter key), use it, jump to next sub-trie
{29 zero bytes}02    // key came from cache, it's next sub-trie (1 byte shorter key), use it, jump to next sub-trie
...
ff                   // key came from cache, it's next sub-trie (1 byte shorter key), use it, jump to next sub-trie
nil                  // db returned nil - means no more keys there, done
```
In practice Trie is not full - it means that after account key `{30 zero bytes}0000` may come `{5 zero bytes}01` and
amount of iterations will not be big.
*/
evmc::bytes32 DbTrieLoader::calculate_root(PrefixSet& account_changes, PrefixSet& storage_changes) {
    auto state{db::open_cursor(txn_, db::table::kHashedAccounts)};
    auto trie_db_cursor{db::open_cursor(txn_, db::table::kTrieOfAccounts)};

    for (Cursor trie{trie_db_cursor, account_changes}; trie.key().has_value();) {
        if (trie.can_skip_state()) {
            SILKWORM_ASSERT(trie.hash() != nullptr);
            hb_.add_branch_node(*trie.key(), *trie.hash(), trie.children_are_in_trie());
        }

        const std::optional<Bytes> uncovered{trie.first_uncovered_prefix()};
        if (uncovered == std::nullopt) {
            // no more uncovered accounts
            break;
        }

        trie.next();

        for (auto acc{state.lower_bound(db::to_slice(*uncovered), /*throw_notfound=*/false)}; acc;
             acc = state.to_next(/*throw_notfound=*/false)) {
            const Bytes unpacked_key{unpack_nibbles(db::from_slice(acc.key))};
            if (trie.key().has_value() && trie.key().value() < unpacked_key) {
                break;
            }
            const auto [account, err]{Account::from_encoded_storage(db::from_slice(acc.value))};
            rlp::success_or_throw(err);

            evmc::bytes32 storage_root{kEmptyRoot};

            if (account.incarnation) {
                const Bytes key_with_inc{db::storage_prefix(db::from_slice(acc.key), account.incarnation)};
                storage_root = calculate_storage_root(key_with_inc, storage_changes);
            }

            hb_.add_leaf(unpacked_key, account.rlp(storage_root));
        }
    }

    return hb_.root_hash();
}

evmc::bytes32 DbTrieLoader::calculate_storage_root(const Bytes& key_with_inc, PrefixSet& changed) {
    auto state{db::open_cursor(txn_, db::table::kHashedStorage)};
    auto trie_db_cursor{db::open_cursor(txn_, db::table::kTrieOfStorage)};

    HashBuilder hb;
    hb.node_collector = [&](ByteView unpacked_storage_key, const Node& node) {
        etl::Entry e{key_with_inc, marshal_node(node)};
        e.key.append(unpacked_storage_key);
        storage_collector_.collect(std::move(e));
    };

    for (Cursor trie{trie_db_cursor, changed, key_with_inc}; trie.key().has_value();) {
        if (trie.can_skip_state()) {
            SILKWORM_ASSERT(trie.hash() != nullptr);
            hb.add_branch_node(*trie.key(), *trie.hash(), trie.children_are_in_trie());
        }

        const std::optional<Bytes> uncovered{trie.first_uncovered_prefix()};
        if (uncovered == std::nullopt) {
            // no more uncovered storage
            break;
        }

        trie.next();

        // TODO (Andrew) consider replacing with cursor_for_each(_multi?)
        for (auto storage{state.lower_bound_multivalue(db::to_slice(key_with_inc), db::to_slice(*uncovered),
                                                       /*throw_notfound=*/false)};
             storage; storage = state.to_current_next_multi(/*throw_notfound=*/false)) {
            const Bytes unpacked_loc{unpack_nibbles(db::from_slice(storage.value).substr(0, kHashLength))};
            if (trie.key().has_value() && trie.key().value() < unpacked_loc) {
                break;
            }

            const ByteView value{db::from_slice(storage.value).substr(kHashLength)};
            rlp_.clear();
            rlp::encode(rlp_, value);
            hb.add_leaf(unpacked_loc, rlp_);
        }
    }

    return hb.root_hash();
}

}  // namespace silkworm::trie
