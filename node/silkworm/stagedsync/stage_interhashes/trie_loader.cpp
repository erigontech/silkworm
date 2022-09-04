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

#include <silkworm/common/rlp_err.hpp>
#include <silkworm/concurrency/signal_handler.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/trie/nibbles.hpp>
#include <silkworm/types/account.hpp>

namespace silkworm::trie {

TrieLoader::TrieLoader(mdbx::txn& txn, PrefixSet* account_changes, PrefixSet* storage_changes,
                       etl::Collector* account_trie_node_collector, etl::Collector* storage_trie_node_collector)
    : txn_{txn},
      account_changes_{account_changes},
      storage_changes_{storage_changes},
      account_trie_node_collector_{account_trie_node_collector},
      storage_trie_node_collector_{storage_trie_node_collector} {
    // Either both or nothing
    if ((account_changes == nullptr) != (storage_changes == nullptr)) {
        throw std::runtime_error("TrieLoader requires account_changes to be both provided or both nullptr");
    }
    if (!account_trie_node_collector_ || !storage_trie_node_collector_) {
        throw std::runtime_error("TrieLoader requires account and storage collectors to be provided");
    }
}

evmc::bytes32 TrieLoader::calculate_root() {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    db::Cursor hashed_accounts(txn_, db::table::kHashedAccounts);
    db::Cursor hashed_storage(txn_, db::table::kHashedStorage);
    db::Cursor trie_accounts(txn_, db::table::kTrieOfAccounts);
    db::Cursor trie_storage(txn_, db::table::kTrieOfStorage);

    // On full regeneration we must assert both trees are empty
    if (!account_changes_) {
        if (!trie_accounts.empty() || !trie_storage.empty()) {
            throw std::domain_error(" full regeneration detected but either " +
                                    std::string(db::table::kTrieOfAccounts.name) + " or " +
                                    std::string(db::table::kTrieOfStorage.name) + " aren't empty");
        }
    }

    Bytes storage_prefix_buffer{};
    storage_prefix_buffer.reserve(db::kHashedStoragePrefixLength);

    HashBuilder account_hash_builder;
    account_hash_builder.node_collector = [&](ByteView nibbled_key, const trie::Node& node) {
        Bytes value{node.state_mask() ? node.encode_for_storage() : Bytes{}};  // Node with no state should be deleted
        account_trie_node_collector_->collect({Bytes{nibbled_key}, value});
    };

    HashBuilder storage_hash_builder;
    storage_hash_builder.node_collector = [&](ByteView nibbled_key, const trie::Node& node) {
        Bytes key{storage_prefix_buffer};
        key.append(nibbled_key);
        Bytes value{node.state_mask() ? node.encode_for_storage() : Bytes{}};  // Node with no state should be deleted
        storage_trie_node_collector_->collect({key, value});
    };

    // Open both tries (Account and Storage) to avoid reallocation of Storage on every contract
    TrieCursor trie_account_cursor(trie_accounts, account_changes_, account_trie_node_collector_);
    TrieCursor trie_storage_cursor(trie_storage, storage_changes_, storage_trie_node_collector_);

    // Begin loop on accounts
    auto trie_account_data{trie_account_cursor.to_prefix({})};
    while (true) {
        if (trie_account_data.first_uncovered.has_value()) {
            auto hashed_account_seek_slice{db::to_slice(trie_account_data.first_uncovered.value())};
            auto hashed_account_data{hashed_account_seek_slice.empty()
                                         ? hashed_accounts.to_first(false)
                                         : hashed_accounts.lower_bound(hashed_account_seek_slice, false)};
            while (hashed_account_data) {
                auto hashed_account_data_key_view{db::from_slice(hashed_account_data.key)};

                if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
                    SignalHandler::throw_if_signalled();
                    std::unique_lock log_lck(log_mtx_);
                    log_key_ = to_hex(hashed_account_data_key_view, true);
                    log_time = now + 2s;
                }

                auto hashed_account_data_key_nibbled{unpack_nibbles(hashed_account_data_key_view)};
                if (trie_account_data.key.has_value() &&
                    trie_account_data.key.value() < hashed_account_data_key_nibbled) {
                    break;
                }

                // Retrieve account data
                const auto [account, err]{Account::from_encoded_storage(db::from_slice(hashed_account_data.value))};
                rlp::success_or_throw(err);

                evmc::bytes32 storage_root{kEmptyRoot};
                if (account.incarnation) {
                    // Calc storage root
                    storage_prefix_buffer.assign(db::storage_prefix(hashed_account_data_key_view, account.incarnation));
                    storage_root = calculate_storage_root(trie_storage_cursor, storage_hash_builder, hashed_storage,
                                                          storage_prefix_buffer);
                }

                account_hash_builder.add_leaf(hashed_account_data_key_nibbled, account.rlp(storage_root));
                hashed_account_data = hashed_accounts.to_next(false);
            }
        }

        // Interrupt loop when no more keys to process
        if (!trie_account_data.key.has_value()) {
            break;
        }

        account_hash_builder.add_branch_node(trie_account_data.key.value(), trie_account_data.hash.value(),
                                             trie_account_data.children_in_trie);

        // If root node added we can exit
        if (trie_account_data.key->empty()) {
            break;
        }

        trie_account_data = trie_account_cursor.to_next();
    }

    auto root_hash{account_hash_builder.root_hash()};
    account_hash_builder.reset();
    return root_hash;
}

evmc::bytes32 TrieLoader::calculate_storage_root(TrieCursor& trie_storage_cursor, HashBuilder& storage_hash_builder,
                                                 db::Cursor& hashed_storage, const Bytes& db_storage_prefix) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    static Bytes rlp_buffer{};

    const auto db_storage_prefix_slice{db::to_slice(db_storage_prefix)};
    auto trie_storage_data{trie_storage_cursor.to_prefix(db_storage_prefix)};
    while (true) {
        if (trie_storage_data.first_uncovered.has_value()) {
            const auto prefix_slice{db::to_slice(trie_storage_data.first_uncovered.value())};
            auto hashed_storage_data{
                hashed_storage.lower_bound_multivalue(db_storage_prefix_slice, prefix_slice, false)};

            while (hashed_storage_data) {
                if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
                    SignalHandler::throw_if_signalled();
                }

                auto hashed_storage_data_value_view{db::from_slice(hashed_storage_data.value)};
                const auto nibbled_location{
                    trie::unpack_nibbles(hashed_storage_data_value_view.substr(0, kHashLength))};
                if (trie_storage_data.key.has_value() && trie_storage_data.key.value() < nibbled_location) {
                    break;
                }

                hashed_storage_data_value_view.remove_prefix(kHashLength);  // Keep value part
                rlp_buffer.clear();
                rlp::encode(rlp_buffer, hashed_storage_data_value_view);
                storage_hash_builder.add_leaf(nibbled_location, rlp_buffer);
                hashed_storage_data = hashed_storage.to_current_next_multi(false);
            }
        }

        // Interrupt loop when no more keys to process
        if (!trie_storage_data.key.has_value()) {
            break;
        }

        storage_hash_builder.add_branch_node(trie_storage_data.key.value(), trie_storage_data.hash.value(),
                                             trie_storage_data.children_in_trie);

        // Have we just sent Storage root for this contract ?
        if (trie_storage_data.key.value().empty()) {
            break;
        }

        trie_storage_data = trie_storage_cursor.to_next();
    }

    auto storage_root{storage_hash_builder.root_hash()};
    storage_hash_builder.reset();
    return storage_root;
}

}  // namespace silkworm::trie
