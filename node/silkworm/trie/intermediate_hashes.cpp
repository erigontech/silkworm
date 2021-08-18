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

#include "intermediate_hashes.hpp"

#include <bitset>

#include <silkworm/common/log.hpp>
#include <silkworm/common/rlp_err.hpp>
#include <silkworm/db/tables.hpp>

namespace silkworm::trie {

AccountTrieCursor::AccountTrieCursor(mdbx::txn&) {}

Bytes AccountTrieCursor::first_uncovered_prefix() {
    // TODO[Issue 179] implement
    return {};
}

std::optional<Bytes> AccountTrieCursor::key() const {
    // TODO[Issue 179] implement
    return std::nullopt;
}

void AccountTrieCursor::next() {
    // TODO[Issue 179] implement
}

bool AccountTrieCursor::can_skip_state() const {
    // TODO[Issue 179] implement
    return false;
}

StorageTrieCursor::StorageTrieCursor(mdbx::txn&) {}

Bytes StorageTrieCursor::seek_to_account(ByteView) {
    // TODO[Issue 179] implement
    return {};
}

Bytes StorageTrieCursor::first_uncovered_prefix() {
    // TODO[Issue 179] implement
    return Bytes(1, '\0');
}

std::optional<Bytes> StorageTrieCursor::key() const {
    // TODO[Issue 179] implement
    return std::nullopt;
}

void StorageTrieCursor::next() {
    // TODO[Issue 179] implement
}

bool StorageTrieCursor::can_skip_state() const {
    // TODO[Issue 179] implement
    return false;
}

DbTrieLoader::DbTrieLoader(mdbx::txn& txn, etl::Collector& account_collector, etl::Collector& storage_collector)
    : txn_{txn}, storage_collector_{storage_collector} {
    hb_.node_collector = [&account_collector](ByteView unpacked_key, const Node& node) {
        if (unpacked_key.empty()) {
            return;
        }

        etl::Entry e;
        e.key = unpacked_key;
        e.value = marshal_node(node);
        account_collector.collect(e);
    };
}

// calculate_root algo:
//  for iterateIHOfAccounts {
//      if canSkipState
//          goto use_account_trie
//
//      for iterateAccounts from prevIH to currentIH {
//          use(account)
//          for iterateIHOfStorage within accountWithIncarnation{
//              if canSkipState
//                  goto use_storage_trie
//
//              for iterateStorage from prevIHOfStorage to currentIHOfStorage {
//                  use(storage)
//              }
//            use_storage_trie:
//              use(ihStorage)
//          }
//      }
//    use_account_trie:
//      use(AccTrie)
//  }
//
// See also
// https://github.com/ledgerwatch/erigon/blob/devel/docs/programmers_guide/guide.md#merkle-trie-root-calculation
evmc::bytes32 DbTrieLoader::calculate_root() {
    auto acc_state{db::open_cursor(txn_, db::table::kHashedAccounts)};
    auto storage_state{db::open_cursor(txn_, db::table::kHashedStorage)};

    StorageTrieCursor storage_trie{txn_};

    for (AccountTrieCursor acc_trie{txn_};; acc_trie.next()) {
        if (acc_trie.can_skip_state()) {
            goto use_account_trie;
        }

        for (auto a{acc_state.lower_bound(db::to_slice(acc_trie.first_uncovered_prefix()), /*throw_notfound*/ false)};
             a.done == true; a = acc_state.to_next(/*throw_notfound*/ false)) {
            const Bytes unpacked_key{unpack_nibbles(db::from_slice(a.key))};
            if (acc_trie.key().has_value() && acc_trie.key().value() < unpacked_key) {
                break;
            }
            const auto [account, err]{decode_account_from_storage(db::from_slice(a.value))};
            rlp::err_handler(err);

            evmc::bytes32 storage_root{kEmptyRoot};

            if (account.incarnation) {
                const Bytes acc_with_inc{db::storage_prefix(db::from_slice(a.key), account.incarnation)};
                HashBuilder storage_hb;
                storage_hb.node_collector = [&](ByteView unpacked_key, const Node& node) {
                    etl::Entry e{acc_with_inc, marshal_node(node)};
                    e.key.append(unpacked_key);
                    storage_collector_.collect(e);
                };

                for (storage_trie.seek_to_account(acc_with_inc);; storage_trie.next()) {
                    if (storage_trie.can_skip_state()) {
                        goto use_storage_trie;
                    }

                    for (auto s{storage_state.lower_bound_multivalue(
                             db::to_slice(acc_with_inc), db::to_slice(storage_trie.first_uncovered_prefix()), false)};
                         s.done == true; s = storage_state.to_current_next_multi(false)) {
                        const ByteView packed_loc{db::from_slice(s.value).substr(0, kHashLength)};
                        const ByteView value{db::from_slice(s.value).substr(kHashLength)};
                        const Bytes unpacked_loc{unpack_nibbles(packed_loc)};
                        if (storage_trie.key().has_value() && storage_trie.key().value() < unpacked_loc) {
                            break;
                        }

                        rlp_.clear();
                        rlp::encode(rlp_, value);
                        storage_hb.add(packed_loc, rlp_);
                    }

                use_storage_trie:
                    if (!storage_trie.key().has_value()) {
                        break;
                    }

                    // TODO[Issue 179] use storage trie
                }

                storage_root = storage_hb.root_hash();
            }

            hb_.add(db::from_slice(a.key), account.rlp(storage_root));
        }

    use_account_trie:
        if (!acc_trie.key().has_value()) {
            break;
        }

        // TODO[Issue 179] use account trie
    }

    return hb_.root_hash();
}

evmc::bytes32 regenerate_intermediate_hashes(mdbx::txn& txn, const char* etl_dir, const evmc::bytes32* expected_root) {
    etl::Collector account_collector{etl_dir};
    etl::Collector storage_collector{etl_dir};
    DbTrieLoader loader{txn, account_collector, storage_collector};
    const evmc::bytes32 root{loader.calculate_root()};
    if (expected_root && root != *expected_root) {
        SILKWORM_LOG(LogLevel::Error) << "Wrong trie root: " << to_hex(root) << ", expected: " << to_hex(*expected_root)
                                      << "\n";
        throw WrongRoot{};
    }
    auto target{db::open_cursor(txn, db::table::kTrieOfAccounts)};
    account_collector.load(target);
    target.close();

    target = db::open_cursor(txn, db::table::kTrieOfStorage);
    storage_collector.load(target);
    target.close();

    return root;
}

evmc::bytes32 increment_intermediate_hashes(mdbx::txn&, const char*, const evmc::bytes32*) {
    // TODO[Issue 179] implement
    throw WrongRoot{};
}

}  // namespace silkworm::trie
