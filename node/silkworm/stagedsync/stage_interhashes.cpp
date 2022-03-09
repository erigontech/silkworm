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

#include <absl/container/btree_set.h>

#include <silkworm/stagedsync/stage_interhashes/trie_loader.hpp>
#include <silkworm/trie/hash_builder.hpp>

namespace silkworm::stagedsync {

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
        }

        if (reached_blocknum % 32 == 0) {
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
        }

        if (reached_blocknum % 16 == 0) {
            throw_if_stopping();
            log_lck.lock();
            current_key_ = std::to_string(reached_blocknum);
            log_lck.unlock();
        }

        changeset_key_view.remove_prefix(8);

        const evmc::address address{to_evmc_address(changeset_key_view)};
        hashed_addresses_it = hashed_addresses.find(address);
        if (hashed_addresses_it == hashed_addresses.end()) {
            const auto hashed_address{keccak256(address.bytes)};
            hashed_addresses_it = hashed_addresses.insert_or_assign(address, hashed_address).first;
        }

        changeset_key_view.remove_prefix(kAddressLength);
        const Bytes incarnation{changeset_key_view};

        while (changeset_data) {
            auto changeset_value_view{db::from_slice(changeset_data.value)};
            const ByteView location{db::from_slice(changeset_data.value).substr(0, kHashLength)};
            const auto hashed_location{keccak256(location)};

            Bytes hashed_key{ByteView{hashed_addresses_it->second.bytes}};
            hashed_key.append(incarnation);
            hashed_key.append(trie::unpack_nibbles(hashed_location.bytes));
            ret.insert(hashed_key);
            changeset_data = storage_changeset.to_current_next_multi(/*throw_notfound=*/false);
        }

        changeset_data = storage_changeset.to_next(/*throw_notfound=*/false);
    }

    return ret;
}

StageResult InterHashes::forward(db::RWTxn& txn) {
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        auto previous_progress{db::stages::read_stage_progress(*txn, stage_name_)};
        auto hashstate_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kHashStateKey)};
        if (previous_progress == hashstate_stage_progress) {
            // Nothing to process
            return StageResult::kSuccess;
        } else if (previous_progress > hashstate_stage_progress) {
            // Something bad had happened. Not possible execution stage is ahead of bodies
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

        reset_log_progress();
        evmc::bytes32 state_root;
        if (!previous_progress || segment_width > 100'000) {
            state_root = regenerate_intermediate_hashes(txn);
        } else {
            // Incremental update
        }

        throw_if_stopping();
        db::stages::write_stage_progress(*txn, db::stages::kHashStateKey, hashstate_stage_progress);
        txn.commit();

    } catch (const StageError& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return static_cast<StageResult>(ex.err());
    } catch (const std::exception& ex) {
        reset_log_progress();
        log::Error(std::string(stage_name_), {"exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    }

    return StageResult::kSuccess;
}

evmc::bytes32 InterHashes::regenerate_intermediate_hashes(db::RWTxn& txn, const evmc::bytes32* expected_root) {
    // Clear any data in target tables
    txn->clear_map(db::table::kTrieOfAccounts.name);
    txn->clear_map(db::table::kTrieOfStorage.name);
    trie::PrefixSet empty;
    return increment_intermediate_hashes(txn, expected_root,  //
                                         /*account_changes=*/empty,
                                         /*storage_changes=*/empty);
}

evmc::bytes32 InterHashes::increment_intermediate_hashes(db::RWTxn& txn, BlockNum from, BlockNum to,
                                                         const evmc::bytes32* expected_root) {
    trie::PrefixSet account_changes{gather_account_changes(txn, from, to)};
    trie::PrefixSet storage_changes{gather_storage_changes(txn, from, to)};
    return increment_intermediate_hashes(txn, expected_root, account_changes, storage_changes);
}

evmc::bytes32 InterHashes::increment_intermediate_hashes(db::RWTxn& txn, const evmc::bytes32* expected_root,
                                                         trie::PrefixSet& account_changes,
                                                         trie::PrefixSet& storage_changes) {
    account_collector_ = std::make_unique<etl::Collector>(node_settings_);
    storage_collector_ = std::make_unique<etl::Collector>(node_settings_);

    trie::DbTrieLoader loader{*txn, *account_collector_, *storage_collector_};
    const evmc::bytes32 root{loader.calculate_root(account_changes, storage_changes)};
    if (expected_root != nullptr && root != *expected_root) {
        std::string what{"Wrong trie root : got " + to_hex(root) + " expected " + to_hex(*expected_root)};
        throw std::runtime_error(what);
    }
    db::Cursor target(txn, db::table::kTrieOfAccounts);
    account_collector_->load(target);
    account_collector_.reset();

    target.bind(txn, db::table::kTrieOfStorage);
    storage_collector_->load(target);
    storage_collector_.reset();

    return root;
}

void InterHashes::reset_log_progress() {
    std::unique_lock log_lck(log_mtx_);
    current_source_.clear();
    current_key_.clear();
}

}  // namespace silkworm::stagedsync
