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

#include "stage_interhashes.hpp"

#include <utility>

#include <absl/container/btree_set.h>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/rlp_err.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/stagedsync/stage_interhashes/trie_cursor.hpp>
#include <silkworm/trie/hash_builder.hpp>

#include "silkworm/types/account.hpp"

namespace silkworm::stagedsync {

StageResult InterHashes::forward(db::RWTxn& txn) {
    StageResult ret{StageResult::kSuccess};

    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        auto previous_progress{get_progress(txn)};
        auto hashstate_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kHashStateKey)};
        if (previous_progress == hashstate_stage_progress) {
            // Nothing to process
            return StageResult::kSuccess;
        } else if (previous_progress > hashstate_stage_progress) {
            // Something bad had happened. Not possible hashstate stage is ahead of bodies
            // Maybe we need to unwind ?
            log::Error() << "Bad progress sequence. InterHashes stage progress " << previous_progress
                         << " while HashState stage " << hashstate_stage_progress;
            return StageResult::kInvalidProgress;
        }

        BlockNum segment_width{hashstate_stage_progress - previous_progress};
        if (segment_width > 16) {
            log::Info("Begin " + std::string(stage_name_),
                      {"from", std::to_string(previous_progress), "to", std::to_string(hashstate_stage_progress)});
        }

        auto header_hash{db::read_canonical_header_hash(*txn, hashstate_stage_progress)};
        SILKWORM_ASSERT(header_hash.has_value());
        auto header{db::read_header(*txn, hashstate_stage_progress, header_hash->bytes)};
        SILKWORM_ASSERT(header.has_value());
        auto expected_state_root{header->state_root};

        reset_log_progress();

        if (!previous_progress || segment_width > 100'000) {
            // Full regeneration
            ret = regenerate_intermediate_hashes(txn, &expected_state_root);
        } else {
            // Incremental update
            ret = increment_intermediate_hashes(txn, previous_progress, hashstate_stage_progress, &expected_state_root);
        }

        success_or_throw(ret);
        throw_if_stopping();
        db::stages::write_stage_progress(*txn, db::stages::kIntermediateHashesKey, hashstate_stage_progress);
        txn.commit();

    } catch (const mdbx::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = StageResult::kDbError;
    } catch (const StageError& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return static_cast<StageResult>(ex.err());
    } catch (const std::exception& ex) {
        reset_log_progress();
        log::Error(std::string(stage_name_), {"exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    }

    return ret;
}

StageResult InterHashes::unwind(db::RWTxn& txn, BlockNum to) {
    (void)txn;
    (void)to;
    return StageResult::kUnknownError;
}

StageResult InterHashes::prune(db::RWTxn&) { return StageResult::kSuccess; }

trie::PrefixSet InterHashes::gather_account_changes(db::RWTxn& txn, BlockNum from, BlockNum to) {
    BlockNum reached_blocknum{0};
    BlockNum expected_blocknum{from + 1};

    std::unique_lock log_lck(log_mtx_);
    current_source_ = std::string(db::table::kAccountChangeSet.name);
    current_key_ = std::to_string(expected_blocknum);
    log_lck.unlock();

    const Bytes starting_key{db::block_key(expected_blocknum)};
    trie::PrefixSet ret;

    // Don't rehash same addresses
    absl::btree_set<evmc::address> unique_addresses{};

    db::Cursor account_changeset(txn, db::table::kAccountChangeSet);
    auto changeset_data{account_changeset.lower_bound(db::to_slice(starting_key), /*throw_notfound=*/false)};

    while (changeset_data) {
        reached_blocknum = endian::load_big_u64(db::from_slice(changeset_data.key).data());
        check_block_sequence(reached_blocknum, expected_blocknum);
        if (reached_blocknum > to) {
            break;
        } else if (reached_blocknum % 32 == 0) {
            throw_if_stopping();
            log_lck.lock();
            current_key_ = std::to_string(reached_blocknum);
            log_lck.unlock();
        }

        while (changeset_data) {
            auto changeset_value_view{db::from_slice(changeset_data.value)};
            evmc::address address{to_evmc_address(changeset_value_view)};
            if (!unique_addresses.contains(address)) {
                const auto hashed_address{keccak256(address)};
                ret.insert(trie::unpack_nibbles(hashed_address.bytes));
                unique_addresses.insert(address);
            }
            changeset_data = account_changeset.to_current_next_multi(/*throw_notfound=*/false);
        }

        ++expected_blocknum;
        changeset_data = account_changeset.to_next(/*throw_notfound=*/false);
    }

    return ret;
}

trie::PrefixSet InterHashes::gather_storage_changes(db::RWTxn& txn, BlockNum from, BlockNum to) {
    BlockNum reached_blocknum{0};
    BlockNum expected_blocknum{from + 1};

    std::unique_lock log_lck(log_mtx_);
    current_source_ = std::string(db::table::kStorageChangeSet.name);
    current_key_ = std::to_string(expected_blocknum);
    log_lck.unlock();

    const Bytes starting_key{db::block_key(expected_blocknum)};
    trie::PrefixSet ret;

    // Don't rehash same addresses
    absl::btree_map<evmc::address, ethash_hash256> hashed_addresses{};
    absl::btree_map<evmc::address, ethash_hash256>::iterator hashed_addresses_it{hashed_addresses.begin()};

    db::Cursor storage_changeset(txn, db::table::kStorageChangeSet);
    auto changeset_data{storage_changeset.lower_bound(db::to_slice(starting_key), /*throw_notfound=*/false)};

    while (changeset_data) {
        auto changeset_key_view{db::from_slice(changeset_data.key)};
        reached_blocknum = endian::load_big_u64(changeset_key_view.data());

        if (reached_blocknum > to) {
            break;
        } else if (reached_blocknum % 16 == 0) {
            throw_if_stopping();
            log_lck.lock();
            current_key_ = std::to_string(reached_blocknum);
            log_lck.unlock();
        }

        changeset_key_view.remove_prefix(sizeof(BlockNum));

        const evmc::address address{to_evmc_address(changeset_key_view)};
        hashed_addresses_it = hashed_addresses.find(address);
        if (hashed_addresses_it == hashed_addresses.end()) {
            const auto hashed_address{keccak256(address.bytes)};
            hashed_addresses_it = hashed_addresses.insert_or_assign(address, hashed_address).first;
        }

        changeset_key_view.remove_prefix(kAddressLength);

        while (changeset_data) {
            auto changeset_value_view{db::from_slice(changeset_data.value)};
            const ByteView location{changeset_value_view.substr(0, kHashLength)};
            const auto hashed_location{keccak256(location)};

            Bytes hashed_key{ByteView{hashed_addresses_it->second.bytes}};
            hashed_key.append(changeset_key_view);
            hashed_key.append(trie::unpack_nibbles(hashed_location.bytes));
            ret.insert(hashed_key);
            changeset_data = storage_changeset.to_current_next_multi(/*throw_notfound=*/false);
        }

        changeset_data = storage_changeset.to_next(/*throw_notfound=*/false);
    }

    return ret;
}

StageResult InterHashes::regenerate_intermediate_hashes(db::RWTxn& txn, const evmc::bytes32* expected_root) {
    StageResult ret{StageResult::kSuccess};
    try {
        // Clear any data in target tables
        txn->clear_map(db::table::kTrieOfAccounts.name);
        txn->clear_map(db::table::kTrieOfStorage.name);
        trie::PrefixSet empty;
        ret = increment_intermediate_hashes(txn, expected_root,  //
                                            /*account_changes=*/empty,
                                            /*storage_changes=*/empty);
    } catch (const mdbx::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = StageResult::kDbError;
    } catch (const StageError& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<StageResult>(ex.err());
    } catch (const std::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = StageResult::kUnexpectedError;
    } catch (...) {
        log::Error(std::string(stage_name_), {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = StageResult::kUnexpectedError;
    }

    return ret;
}

StageResult InterHashes::increment_intermediate_hashes(db::RWTxn& txn, BlockNum from, BlockNum to,
                                                       const evmc::bytes32* expected_root) {
    std::unique_lock log_lck(log_mtx_);
    incremental_ = true;
    log_lck.unlock();
    StageResult ret{StageResult::kSuccess};

    try {
        trie::PrefixSet account_changes{gather_account_changes(txn, from, to)};
        trie::PrefixSet storage_changes{gather_storage_changes(txn, from, to)};

        log_lck.lock();
        current_source_.clear();
        current_key_.clear();
        log_lck.unlock();

        ret = increment_intermediate_hashes(txn, expected_root, account_changes, storage_changes);

    } catch (const mdbx::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = StageResult::kDbError;
    } catch (const StageError& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<StageResult>(ex.err());
    } catch (const std::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = StageResult::kUnexpectedError;
    } catch (...) {
        log::Error(std::string(stage_name_), {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = StageResult::kUnexpectedError;
    }

    return ret;
}

StageResult InterHashes::increment_intermediate_hashes(db::RWTxn& txn, const evmc::bytes32* expected_root,
                                                       trie::PrefixSet& account_changes,
                                                       trie::PrefixSet& storage_changes) {
    account_collector_ = std::make_unique<etl::Collector>(node_settings_);
    storage_collector_ = std::make_unique<etl::Collector>(node_settings_);

    const evmc::bytes32 root{calculate_root(txn, account_changes, storage_changes)};
    if (expected_root != nullptr && root != *expected_root) {
        account_collector_.reset();
        storage_collector_.reset();
        log::Error("Wrong trie root", {"expected", to_hex(*expected_root, true), "got", to_hex(root, true)});
        return StageResult::kWrongStateRoot;
    }

    std::unique_lock log_lck(log_mtx_);
    loading_ = true;
    loading_collector_ = std::move(account_collector_);
    current_target_ = std::string(db::table::kTrieOfAccounts.name);
    log_lck.unlock();

    db::Cursor target(txn, db::table::kTrieOfAccounts);
    MDBX_put_flags_t flags{target.get_map_stat().ms_entries ? MDBX_put_flags_t::MDBX_UPSERT
                                                            : MDBX_put_flags_t::MDBX_APPEND};
    loading_collector_->load(target, nullptr, flags);

    log_lck.lock();
    loading_collector_ = std::move(storage_collector_);
    current_target_ = std::string(db::table::kTrieOfStorage.name);
    log_lck.unlock();

    target.bind(txn, db::table::kTrieOfStorage);
    flags = target.get_map_stat().ms_entries ? MDBX_put_flags_t::MDBX_UPSERT : MDBX_put_flags_t::MDBX_APPEND;
    loading_collector_->load(target, nullptr, flags);

    log_lck.lock();
    current_target_.clear();
    loading_ = false;
    loading_collector_.reset();
    log_lck.unlock();

    return StageResult::kSuccess;
}

evmc::bytes32 InterHashes::calculate_root(db::RWTxn& txn, trie::PrefixSet& account_changes,
                                          trie::PrefixSet& storage_changes) {
    db::Cursor hashed_accounts(txn, db::table::kHashedAccounts);
    db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);

    trie::HashBuilder hash_builder;
    hash_builder.node_collector = [&](ByteView unpacked_key, const trie::Node& node) {
        if (!unpacked_key.empty()) {
            account_collector_->collect({Bytes(unpacked_key), marshal_node(node)});
        }
    };

    trie::Cursor trie_cursor{trie_accounts, account_changes};
    while (trie_cursor.key().has_value()) {
        if (trie_cursor.can_skip_state()) {
            SILKWORM_ASSERT(trie_cursor.hash() != nullptr);
            hash_builder.add_branch_node(*trie_cursor.key(), *trie_cursor.hash(), trie_cursor.children_are_in_trie());
        }

        const std::optional<Bytes> uncovered{trie_cursor.first_uncovered_prefix()};
        if (!uncovered.has_value()) {
            // no more uncovered accounts
            break;
        }

        trie_cursor.next();
        auto hashed_account_data{hashed_accounts.lower_bound(db::to_slice(*uncovered), /*throw_notfound=*/false)};
        size_t log_trigger_counter{1};
        while (hashed_account_data) {
            const auto data_key_view{db::from_slice(hashed_account_data.key)};

            if (!--log_trigger_counter) {
                std::unique_lock<std::mutex> log_lck(log_mtx_);
                current_source_ = "HashedState";
                current_key_ = abridge(to_hex(data_key_view, true), 16);
                log_lck.unlock();
                throw_if_stopping();
                log_trigger_counter = 32;
            }

            const Bytes unpacked_key{trie::unpack_nibbles(data_key_view)};
            if (trie_cursor.key().has_value() && trie_cursor.key().value() < unpacked_key) {
                break;
            }
            const auto [account, err]{Account::from_encoded_storage(db::from_slice(hashed_account_data.value))};
            rlp::success_or_throw(err);

            evmc::bytes32 storage_root{kEmptyRoot};
            if (account.incarnation) {
                const Bytes key_with_incarnation{db::storage_prefix(data_key_view, account.incarnation)};
                storage_root = calculate_storage_root(txn, key_with_incarnation, storage_changes);
            }

            hash_builder.add_leaf(unpacked_key, account.rlp(storage_root));
            hashed_account_data = hashed_accounts.to_next(/*throw_notfound=*/false);
        }
    }

    return hash_builder.root_hash();
}

evmc::bytes32 InterHashes::calculate_storage_root(db::RWTxn& txn, const Bytes& db_storage_prefix,
                                                  trie::PrefixSet& storage_changes) {
    static Bytes rlp{};
    db::Cursor hashed_storage(txn, db::table::kHashedStorage);
    db::Cursor trie_storage(txn, db::table::kTrieOfStorage);

    trie::HashBuilder hash_builder;
    hash_builder.node_collector = [&](ByteView unpacked_storage_key, const trie::Node& node) {
        etl::Entry entry{db_storage_prefix, marshal_node(node)};
        entry.key.append(unpacked_storage_key);
        storage_collector_->collect(std::move(entry));
    };

    trie::Cursor trie_cursor{trie_storage, storage_changes, db_storage_prefix};
    while (trie_cursor.key().has_value()) {
        if (trie_cursor.can_skip_state()) {
            SILKWORM_ASSERT(trie_cursor.hash() != nullptr);
            hash_builder.add_branch_node(*trie_cursor.key(), *trie_cursor.hash(), trie_cursor.children_are_in_trie());
        }

        const std::optional<Bytes> uncovered{trie_cursor.first_uncovered_prefix()};
        if (!uncovered.has_value()) {
            // no more uncovered accounts
            break;
        }

        trie_cursor.next();
        auto hashed_storage_data{hashed_storage.lower_bound_multivalue(db::to_slice(db_storage_prefix),
                                                                       db::to_slice(*uncovered),
                                                                       /*throw_notfound=*/false)};
        while (hashed_storage_data) {
            const ByteView data_value_view{db::from_slice(hashed_storage_data.value)};
            const Bytes unpacked_location{trie::unpack_nibbles(data_value_view.substr(0, kHashLength))};
            if (trie_cursor.key().has_value() && trie_cursor.key().value() < unpacked_location) {
                break;
            }
            const ByteView value{data_value_view.substr(kHashLength)};
            rlp.clear();
            rlp::encode(rlp, value);
            hash_builder.add_leaf(unpacked_location, rlp);

            hashed_storage_data = hashed_storage.to_current_next_multi(/*throw_notfound=*/false);
        }
    }

    return hash_builder.root_hash();
}

void InterHashes::reset_log_progress() {
    std::unique_lock log_lck(log_mtx_);
    current_source_.clear();
    current_key_.clear();
}

std::vector<std::string> InterHashes::get_log_progress() {
    std::unique_lock log_lck(log_mtx_);
    std::vector<std::string> ret{};
    ret.insert(ret.end(), {"mode", (incremental_ ? "incr" : "full")});
    if (loading_) {
        ret.insert(ret.end(), {"to", current_target_});
        if (loading_collector_) {
            current_key_ = abridge(loading_collector_->get_load_key(), kAddressLength * 2 + 2);
            ret.insert(ret.end(), {"key", current_key_});
        } else {
            current_key_.clear();
        }
    } else {
        ret.insert(ret.end(), {"from", current_source_, "key", current_key_});
    }
    return ret;
}

}  // namespace silkworm::stagedsync
