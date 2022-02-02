/*
   Copyright 2021-2022 The Silkworm Authors

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

#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/etl/collector.hpp>

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

StageResult HashState::forward(db::RWTxn& txn) {
    if (is_stopping()) {
        return StageResult::kAborted;
    }

    // Check stage boundaries from previous execution and previous stage execution
    auto previous_progress{db::stages::read_stage_progress(*txn, stage_name_)};
    auto execution_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kExecutionKey)};
    if (previous_progress == execution_stage_progress) {
        // Nothing to process
        return StageResult::kSuccess;
    } else if (previous_progress > execution_stage_progress) {
        // Something bad had happened. Not possible execution stage is ahead of bodies
        // Maybe we need to unwind ?
        log::Error() << "Bad progress sequence. HashState stage progress " << previous_progress
                     << " while Execution stage " << execution_stage_progress;
        return StageResult::kInvalidProgress;
    }

    if (execution_stage_progress - previous_progress > 16) {
        log::Info("Begin " + std::string(stage_name_),
                  {"from", std::to_string(previous_progress), "to", std::to_string(execution_stage_progress)});
    }

    reset_log_progress();

    try {
        if (!previous_progress) {
            StageResult result{hash_from_plainstate(txn)};
            collector_->clear();
            reset_log_progress();
            if (result != StageResult::kSuccess) {
                return result;
            }
            result = hash_from_plaincode(txn);
            collector_->clear();
            reset_log_progress();
            if (result != StageResult::kSuccess) {
                return result;
            }

        } else {
            StageResult result{hash_from_account_changeset(txn, previous_progress, execution_stage_progress)};
            reset_log_progress();
            if (result != StageResult::kSuccess) {
                return result;
            }
            result = hash_from_storage_changeset(txn, previous_progress, execution_stage_progress);
            reset_log_progress();
            if (result != StageResult::kSuccess) {
                return result;
            }
        }

        if (!is_stopping()) {
            db::stages::write_stage_progress(*txn, db::stages::kHashStateKey, execution_stage_progress);
            txn.commit();
            return StageResult::kSuccess;
        }
        return StageResult::kAborted;

    } catch (const std::exception& ex) {
        log::Error(std::string(stage_name_), {"exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    }
}

StageResult HashState::unwind(db::RWTxn& txn, BlockNum to) {
    if (is_stopping()) {
        return StageResult::kAborted;
    }

    auto previous_progress{db::stages::read_stage_progress(*txn, stage_name_)};
    if (to >= previous_progress) {
        // Nothing to unwind actually
        return StageResult::kSuccess;
    }
    if (previous_progress - to > 16) {
        log::Info("Begin " + std::string(stage_name_) + " unwind",
                  {"from", std::to_string(previous_progress), "to", std::to_string(to)});
    }

    reset_log_progress();

    try {
        success_or_throw(unwind_from_account_changeset(txn, previous_progress, to));
        reset_log_progress();

        success_or_throw(unwind_from_storage_changeset(txn, previous_progress, to));
        reset_log_progress();

        if (!is_stopping()) {
            db::stages::write_stage_progress(*txn, db::stages::kHashStateKey, to);
            txn.commit();
            return StageResult::kSuccess;
        }

        return StageResult::kAborted;

    } catch (const std::exception& ex) {
        log::Error(std::string(stage_name_), {"exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    }
}

StageResult HashState::prune(db::RWTxn&) {
    // HashState does not prune
    return StageResult::kSuccess;
}

StageResult HashState::hash_from_plainstate(db::RWTxn& txn) {
    try {
        auto source{db::open_cursor(*txn, db::table::kPlainState)};
        auto data{source.to_first(/*throw_notfound=*/false)};
        if (!data.done) {
            // Table empty. Nothing to process
            return StageResult::kSuccess;
        }

        // TODO(Andrea) Maybe introduce an assertion for target tables to be empty ?
        // TODO(Andrea) This is all about hashing. Parallelize !

        /*
         * This relies on the assumption previous execution stage has completed correctly
         * and we do nothing more than hashing keys already present in PlainState either
         * to HashedAccount or to HashedStorage. We don't need to check an upper block
         * limit as PlainState holds info up to to highest executed block
         */

        evmc::address last_address{};
        ethash_hash256 address_hash{keccak256(last_address.bytes)};  // We might have all zeroed addresses ?

        operation_ = OperationType::Forward;
        current_source_ = std::string(db::table::kPlainState.name);
        current_key_ = to_hex(last_address.bytes, /*with_prefix=*/true);

        // New Hashed Storage Entry Key (72 bytes)
        // + Address hash  (32 bytes)
        // + Incarnation   ( 8 bytes)
        // + Location hash (32 bytes)
        Bytes etl_storage_entry_key(72, '\0');

        // Hash accounts
        while (data) {
            auto data_key_view{db::from_slice(data.key)};

            // We're reading PlainState which keys are ordered by address (always initial 20 bytes of key)
            // Rehash the address only when changes
            if (std::memcmp(data_key_view.data(), last_address.bytes, kAddressLength) != 0) {
                last_address = to_evmc_address(data_key_view);
                address_hash = keccak256(last_address.bytes);
                current_key_ = to_hex(last_address.bytes, /*with_prefix=*/true);
            }

            if (data.key.length() == kAddressLength) {
                // Hash account
                // data.key == Address
                // data.value == Account encoded for storage (must exist)
                if (!data.value.length()) {
                    const std::string what("Unexpected empty value in PlainState for Account " + current_key_);
                    throw std::runtime_error(what);
                }

                etl::Entry entry{Bytes(address_hash.bytes, kHashLength), Bytes{db::from_slice(data.value)}};
                collector_->collect(std::move(entry));
                if (collector_->size() % 128 == 0 && is_stopping()) {
                    return StageResult::kAborted;
                }
            } else if (data.key.length() == db::kPlainStoragePrefixLength) {
                // Hash storage
                // data.key           == Address + Incarnation
                // data.value (multi) == Location + zeroless Value

                // See above for allocation
                std::memcpy(&etl_storage_entry_key[0], address_hash.bytes, kHashLength);
                std::memcpy(&etl_storage_entry_key[kHashLength], &data_key_view[kAddressLength],
                            db::kIncarnationLength);

                // Iterate dupkeys only to avoid re-hashing of same address
                while (data) {
                    if (!(data.value.length() > kHashLength)) {
                        const auto incarnation{endian::load_big_u64(&data_key_view[kAddressLength])};
                        const std::string what("Unexpected empty value in PlainState for Account " + current_key_ +
                                               " incarnation " + std::to_string(incarnation));
                        throw std::runtime_error(what);
                    }

                    /*
                     * NOTE !
                     * Destination table kHashedStorage is dup-sorted but as Collector implements sorting only on entry
                     * key here we have to build the entry key as hashed address + incarnation + hashed storage location
                     * eventually leaving entry value to only hashed storage value. This ensures entries are collected
                     * and sorted properly and eventually the loader will move back hashed storage location in the value
                     * part of the db record. This way we can reliably insert records using MDBX_APPENDDUP
                     */

                    auto data_value_view{db::from_slice(data.value)};
                    std::memcpy(&etl_storage_entry_key[kHashLength + db::kIncarnationLength],
                                keccak256(data_value_view.substr(0, kHashLength)).bytes, kHashLength);
                    data_value_view.remove_prefix(kHashLength);
                    etl::Entry entry{etl_storage_entry_key, Bytes{data_value_view}};
                    collector_->collect(std::move(entry));
                    if (collector_->size() % 128 == 0 && is_stopping()) {
                        return StageResult::kAborted;
                    }
                    data = source.to_current_next_multi(false);
                }

            } else {
                std::string what{"Unexpected key length " + std::to_string(data.key.length())};
                throw std::runtime_error(what);
            }

            data = source.to_next(/*throw_notfound=*/false);
        }

        if (!is_stopping()) {
            if (!collector_->empty()) {
                auto account_target = db::open_cursor(*txn, db::table::kHashedAccounts);
                auto storage_target = db::open_cursor(*txn, db::table::kHashedStorage);

                // ETL key contains hashed location; for DB put we need to move it from key to value
                const etl::LoadFunc load_func = [&storage_target](const etl::Entry& entry, mdbx::cursor& target,
                                                                  MDBX_put_flags_t) -> void {
                    if (entry.value.empty()) {
                        return;
                    }

                    if (entry.key.length() == kHashLength) {
                        mdbx::slice k{entry.key.data(), entry.key.length()};
                        mdbx::slice v{entry.value.data(), entry.value.length()};
                        mdbx::error::success_or_throw(target.put(k, &v, MDBX_APPEND));
                    } else if (entry.key.length() == db::kHashedStoragePrefixLength + kHashLength) {
                        Bytes new_value(kHashLength + entry.value.length(), '\0');
                        std::memcpy(&new_value[0], &entry.key[db::kHashedStoragePrefixLength], kHashLength);
                        std::memcpy(&new_value[kHashLength], entry.value.data(), entry.value.length());
                        mdbx::slice k{entry.key.data(), db::kHashedStoragePrefixLength};
                        mdbx::slice v{new_value.data(), new_value.length()};
                        mdbx::error::success_or_throw(storage_target.put(k, &v, MDBX_APPENDDUP));
                    } else {
                        std::string what{"Unexpected key length " + std::to_string(entry.key.length()) +
                                         " in PlainState"};
                        throw std::runtime_error(what);
                    }
                };

                current_target_ =
                    std::string(db::table::kHashedAccounts.name) + "+" + std::string(db::table::kHashedStorage.name);
                loading_ = true;
                collector_->load(account_target, load_func, MDBX_put_flags_t::MDBX_APPENDDUP);
                loading_ = false;
            }
        } else {
            return StageResult::kAborted;
        }

        source.close();
        return is_stopping() ? StageResult::kAborted : StageResult::kSuccess;

    } catch (const mdbx::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return StageResult::kDbError;
    } catch (const std::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    } catch (...) {
        log::Error(std::string(stage_name_), {"function", std::string(__FUNCTION__), "exception", "undefined"});
        return StageResult::kUnexpectedError;
    }
}

StageResult HashState::hash_from_plaincode(db::RWTxn& txn) {
    auto source{db::open_cursor(*txn, db::table::kPlainContractHash)};
    auto data{source.to_first(/*throw_notfound=*/false)};
    if (!data.done) {
        // Table empty. Nothing to process
        return StageResult::kSuccess;
    }

    try {
        // TODO(Andrea) Maybe introduce an assertion for target table to be empty ?

        evmc::address last_address{};

        operation_ = OperationType::Forward;
        current_source_ = std::string(db::table::kPlainContractHash.name);
        current_key_ = to_hex(last_address.bytes, /*with_prefix=*/true);

        Bytes new_key(db::kHashedStoragePrefixLength, '\0');

        while (data) {
            if (data.key.length() != kAddressLength + db::kIncarnationLength) {
                std::string what{"Unexpected key len " + std::to_string(data.key.length())};
                throw std::runtime_error(what);
            }

            auto data_key_view{db::from_slice(data.key)};

            // We're reading PlainCodeHash which keys are ordered by address (always initial 20 bytes of key)
            // Rehash the address only when changes
            if (std::memcmp(data_key_view.data(), last_address.bytes, kAddressLength) != 0) {
                last_address = to_evmc_address(data_key_view);
                current_key_ = to_hex(last_address.bytes, /*with_prefix=*/true);
                const auto address_hash{keccak256(last_address.bytes)};
                std::memcpy(&new_key[0], address_hash.bytes, kHashLength);
            }

            std::memcpy(&new_key[kHashLength], &data_key_view[kAddressLength], db::kIncarnationLength);

            etl::Entry entry{new_key, Bytes{db::from_slice(data.value)}};
            collector_->collect(std::move(entry));
            if (collector_->size() % 128 == 0) {
                current_key_ = abridge(to_hex(db::from_slice(data.key), /*with_prefix=*/true), kAddressLength * 2 + 2);
                if (is_stopping()) {
                    return StageResult::kAborted;
                }
            }
            data = source.to_next(/*throw_notfound=*/false);
        }
        source.close();
        if (!is_stopping()) {
            if (!collector_->empty()) {
                source = db::open_cursor(*txn, db::table::kHashedCodeHash);
                current_target_ = std::string(db::table::kHashedCodeHash.name);
                loading_ = true;
                collector_->load(source, nullptr, MDBX_put_flags_t::MDBX_APPEND);
                loading_ = false;
            }
            return StageResult::kSuccess;
        }
        return StageResult::kAborted;

    } catch (const mdbx::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return StageResult::kDbError;
    } catch (const std::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    } catch (...) {
        log::Error(std::string(stage_name_), {"function", std::string(__FUNCTION__), "exception", "undefined"});
        return StageResult::kUnexpectedError;
    }
}

StageResult HashState::hash_from_account_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to) {
    try {
        /*
         * 1) Read AccountChangeSet from previous_progress to 'to'
         * 2) For each address changed hash it and lookup current value from PlainState
         * 3) Process the collected list and write values into Hashed tables (Account and Code)
         */

        BlockNum reached_blocknum{0};
        BlockNum expected_blocknum{previous_progress + 1};
        ChangedAddresses changed_addresses{};

        operation_ = OperationType::Forward;
        incremental_ = true;
        current_source_ = std::string(db::table::kAccountChangeSet.name);
        current_key_ = std::to_string(expected_blocknum);

        auto source_initial_key{db::block_key(expected_blocknum)};
        auto source_changeset{db::open_cursor(*txn, db::table::kAccountChangeSet)};
        auto source_plainstate{db::open_cursor(*txn, db::table::kPlainState)};
        auto changeset_data{source_changeset.lower_bound(db::to_slice(source_initial_key),
                                                         /*throw_notfound=*/true)};  // Initial record MUST be found
        size_t counter{0};
        while (changeset_data.done) {
            reached_blocknum = endian::load_big_u64(db::from_slice(changeset_data.key).data());
            if (reached_blocknum > to) {
                break;
            }
            if (reached_blocknum != expected_blocknum) {
                log::Error("Bad " + current_source_ + " sequence", {"expected block", std::to_string(expected_blocknum),
                                                                    "actual block", std::to_string(reached_blocknum)});
                return StageResult::kBadChainSequence;
            }
            while (changeset_data) {
                auto changeset_value_view{db::from_slice(changeset_data.value)};
                evmc::address address{to_evmc_address(changeset_value_view)};
                if (!changed_addresses.contains(address)) {
                    auto address_hash{to_bytes32(keccak256(address.bytes).bytes)};
                    auto plainstate_data{source_plainstate.find(db::to_slice(address.bytes), /*throw_notfound=*/false)};
                    if (plainstate_data.done) {
                        Bytes current_value{db::from_slice(plainstate_data.value)};
                        changed_addresses[address] = std::make_pair(address_hash, current_value);
                    } else {
                        changed_addresses[address] = std::make_pair(address_hash, Bytes());
                    }
                }
                if (++counter == 128) {
                    counter = 0;
                    current_key_ = std::to_string(reached_blocknum);
                    if (is_stopping()) {
                        return StageResult::kAborted;
                    }
                }
                changeset_data = source_changeset.to_current_next_multi(/*throw_notfound=*/false);
            }
            ++expected_blocknum;
            changeset_data = source_changeset.to_next(/*throw_notfound=*/false);
        }
        source_changeset.close();
        source_plainstate.close();
        counter = 0;
        return write_changes_from_changed_addresses(txn, changed_addresses);

    } catch (const mdbx::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return StageResult::kDbError;
    } catch (const std::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    } catch (...) {
        log::Error(std::string(stage_name_), {"function", std::string(__FUNCTION__), "exception", "undefined"});
        return StageResult::kUnexpectedError;
    }
}

StageResult HashState::hash_from_storage_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to) {
    try {
        /*
         * 1) Read StorageChangeSet from previous_progress to 'to'
         * 2) For each address + incarnation changed hash it and lookup current value from PlainState
         * 3) Process the collected list and write values into HashedStorage
         */

        BlockNum reached_blocknum{0};

        db::StorageChanges storage_changes{};
        absl::btree_map<evmc::address, evmc::bytes32> hashed_addresses{};

        operation_ = OperationType::Forward;
        incremental_ = true;
        current_source_ = std::string(db::table::kStorageChangeSet.name);
        current_key_ = std::to_string(previous_progress + 1);

        auto source_changeset{db::open_cursor(*txn, db::table::kStorageChangeSet)};
        auto source_plainstate{db::open_cursor(*txn, db::table::kPlainState)};

        auto source_initial_key{db::block_key(previous_progress + 1)};
        auto changeset_data{source_changeset.lower_bound(db::to_slice(source_initial_key), /*throw_notfound=*/true)};
        auto counter{0};

        while (changeset_data.done) {
            auto changeset_key_view{db::from_slice(changeset_data.key)};
            reached_blocknum = endian::load_big_u64(changeset_key_view.data());
            if (reached_blocknum > to) {
                break;
            }
            changeset_key_view.remove_prefix(8);
            evmc::address address{to_evmc_address(changeset_key_view)};
            changeset_key_view.remove_prefix(kAddressLength);
            const auto incarnation{endian::load_big_u64(changeset_key_view.data())};
            if (!incarnation) {
                throw std::runtime_error("Unexpected EOA in StorageChangeset");
            }
            if (!hashed_addresses.contains(address)) {
                hashed_addresses[address] = to_bytes32(keccak256(address.bytes).bytes);
                storage_changes[address].insert_or_assign(incarnation, absl::btree_map<evmc::bytes32, Bytes>());
            }

            Bytes plain_storage_prefix{db::storage_prefix(address, incarnation)};

            while (changeset_data.done) {
                auto changeset_value_view{db::from_slice(changeset_data.value)};
                auto location{to_bytes32(changeset_value_view)};
                if (!storage_changes[address][incarnation].contains(location)) {
                    auto plain_state_value{db::find_value_suffix(source_plainstate, plain_storage_prefix, location)};
                    storage_changes[address][incarnation].insert_or_assign(location,
                                                                           plain_state_value.value_or(Bytes()));
                }
                changeset_data = source_changeset.to_current_next_multi(/*throw_notfound=*/false);
                if (++counter == 128) {
                    counter = 0;
                    current_key_ = std::to_string(reached_blocknum);
                    if (is_stopping()) {
                        return StageResult::kAborted;
                    }
                }
            }
            changeset_data = source_changeset.to_next(/*throw_notfound=*/false);
        }

        // Load data
        if (!storage_changes.empty()) {
            auto target_hashed_storage{db::open_cursor(*txn, db::table::kHashedStorage)};
            loading_ = true;
            current_target_ = std::string(db::table::kHashedStorage.name);
            Bytes hashed_storage_prefix(db::kHashedStoragePrefixLength, '\0');  // One allocation only
            for (const auto& [address, data] : storage_changes) {
                if (++counter == 128) {
                    counter = 0;
                    current_key_ = std::to_string(reached_blocknum);
                    if (is_stopping()) {
                        return StageResult::kAborted;
                    }
                }

                std::memcpy(&hashed_storage_prefix[0], hashed_addresses[address].bytes, kHashLength);
                current_key_ = to_hex(address, true);
                for (const auto& [incarnation, data1] : data) {
                    endian::store_big_u64(&hashed_storage_prefix[kHashLength], incarnation);
                    for (const auto& [location, value] : data1) {
                        auto hashed_location{keccak256(location.bytes)};
                        db::upsert_storage_value(target_hashed_storage, hashed_storage_prefix, hashed_location.bytes,
                                                 value);
                    }
                }
            }
        }

        loading_ = false;
        return StageResult::kSuccess;

    } catch (const mdbx::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return StageResult::kDbError;
    } catch (const std::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    } catch (...) {
        log::Error(std::string(stage_name_), {"function", std::string(__FUNCTION__), "exception", "undefined"});
        return StageResult::kUnexpectedError;
    }
}

StageResult HashState::unwind_from_account_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to) {
    try {
        /*
         * This behaves pretty much similar to hash_from_account_changeset with one major difference:
         * as AccountChangeset records the state of an account at previous block we take the status
         * from the changeset itself. Say we need to unwind to block 990 from 1000. We begin from
         * block 991 (which records a change has been made by block 991 and the value is the one
         * which was at block 990). See tables kAccountChangeSet for reference
         *
         * 1) Read AccountChangeSet from `to+1` to 'previous_progress'
         * 2) For each address changed hash it and take the value of previous block
         * 3) Process the collected list and write values into Hashed tables (Account and Code)
         */

        BlockNum reached_blocknum{0};
        BlockNum expected_blocknum{to + 1};
        ChangedAddresses changed_addresses{};

        operation_ = OperationType::Unwind;
        current_source_ = std::string(db::table::kAccountChangeSet.name);
        current_key_ = std::to_string(expected_blocknum);

        auto source_initial_key{db::block_key(expected_blocknum)};
        auto source_changeset{db::open_cursor(*txn, db::table::kAccountChangeSet)};
        auto changeset_data{source_changeset.lower_bound(db::to_slice(source_initial_key),
                                                         /*throw_notfound=*/true)};  // Initial record MUST be found

        size_t counter{0};
        while (changeset_data.done) {
            reached_blocknum = endian::load_big_u64(db::from_slice(changeset_data.key).data());
            if (reached_blocknum > previous_progress) {
                break;
            }
            if (reached_blocknum != expected_blocknum) {
                log::Error("Bad " + current_source_ + " sequence", {"expected block", std::to_string(expected_blocknum),
                                                                    "actual block", std::to_string(reached_blocknum)});
                return StageResult::kBadChainSequence;
            }
            while (changeset_data) {
                auto changeset_value_view{db::from_slice(changeset_data.value)};
                evmc::address address{to_evmc_address(changeset_value_view)};

                if (!changed_addresses.contains(address)) {
                    changeset_value_view.remove_prefix(kAddressLength);
                    auto address_hash{to_bytes32(keccak256(address.bytes).bytes)};
                    Bytes previous_value(changeset_value_view.data(), changeset_value_view.length());
                    changed_addresses[address] = std::make_pair(address_hash, previous_value);
                }
                if (++counter == 128) {
                    counter = 0;
                    current_key_ = std::to_string(reached_blocknum);
                    if (is_stopping()) {
                        return StageResult::kAborted;
                    }
                }
                changeset_data = source_changeset.to_current_next_multi(/*throw_notfound=*/false);
            }
            ++expected_blocknum;
            changeset_data = source_changeset.to_next(/*throw_notfound=*/false);
        }
        source_changeset.close();
        counter = 0;
        return write_changes_from_changed_addresses(txn, changed_addresses);

    } catch (const mdbx::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return StageResult::kDbError;
    } catch (const std::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    } catch (...) {
        log::Error(std::string(stage_name_), {"function", std::string(__FUNCTION__), "exception", "undefined"});
        return StageResult::kUnexpectedError;
    }
}

StageResult HashState::unwind_from_storage_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to) {
    try {
        /*
         * This behaves pretty much similar to hash_from_storage_changeset with one major difference:
         * as StorageChangeset records the state of an account at previous block we take the status
         * from the changeset itself. Say we need to unwind to block 990 from 1000. We begin from
         * block 991 (which records a change has been made by block 991 and the value is the one
         * which was at block 990). See tables kAccountChangeSet for reference
         *
         * 1) Read StorageChangeSet from `to+1` to 'previous_progress'
         * 2) For each address + incarnation changed hash it and take previous value
         * 3) Process the collected list and write values into HashedStorage
         */

        BlockNum reached_blocknum{0};

        db::StorageChanges storage_changes{};
        absl::btree_map<evmc::address, evmc::bytes32> hashed_addresses{};

        operation_ = OperationType::Unwind;
        incremental_ = true;
        current_source_ = std::string(db::table::kStorageChangeSet.name);
        current_key_ = std::to_string(to + 1);

        auto source_changeset{db::open_cursor(*txn, db::table::kStorageChangeSet)};
        auto source_initial_key{db::block_key(to + 1)};
        auto changeset_data{source_changeset.lower_bound(db::to_slice(source_initial_key), /*throw_notfound=*/true)};
        auto counter{0};

        while (changeset_data.done) {
            auto changeset_key_view{db::from_slice(changeset_data.key)};
            reached_blocknum = endian::load_big_u64(changeset_key_view.data());
            if (reached_blocknum > previous_progress) {
                break;
            }
            changeset_key_view.remove_prefix(8);
            evmc::address address{to_evmc_address(changeset_key_view)};
            changeset_key_view.remove_prefix(kAddressLength);
            const auto incarnation{endian::load_big_u64(changeset_key_view.data())};
            if (!incarnation) {
                throw std::runtime_error("Unexpected EOA in StorageChangeset");
            }
            if (!hashed_addresses.contains(address)) {
                hashed_addresses[address] = to_bytes32(keccak256(address.bytes).bytes);
                storage_changes[address].insert_or_assign(incarnation, absl::btree_map<evmc::bytes32, Bytes>());
            }

            while (changeset_data.done) {
                auto changeset_value_view{db::from_slice(changeset_data.value)};
                auto location{to_bytes32(changeset_value_view)};
                if (!storage_changes[address][incarnation].contains(location)) {
                    changeset_value_view.remove_prefix(kHashLength);
                    Bytes previous_value{changeset_value_view};
                    storage_changes[address][incarnation].insert_or_assign(location, previous_value);
                }
                changeset_data = source_changeset.to_current_next_multi(/*throw_notfound=*/false);
                if (++counter == 128) {
                    counter = 0;
                    current_key_ = std::to_string(reached_blocknum);
                    if (is_stopping()) {
                        return StageResult::kAborted;
                    }
                }
            }
            changeset_data = source_changeset.to_next(/*throw_notfound=*/false);
        }

        return write_changes_from_changed_storage(txn, storage_changes, hashed_addresses);

    } catch (const mdbx::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return StageResult::kDbError;
    } catch (const std::exception& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    } catch (...) {
        log::Error(std::string(stage_name_), {"function", std::string(__FUNCTION__), "exception", "undefined"});
        return StageResult::kUnexpectedError;
    }
}

StageResult HashState::write_changes_from_changed_addresses(db::RWTxn& txn, ChangedAddresses& changed_addresses) {
    size_t counter{0};
    current_target_ = std::string(db::table::kHashedAccounts.name) + " " + std::string(db::table::kHashedCodeHash.name);
    loading_ = true;
    current_key_ = to_hex(changed_addresses.begin()->first.bytes, /*with_prefix=*/true);
    auto source_plaincode{db::open_cursor(*txn, db::table::kPlainContractHash)};
    auto target_hashed_accounts{db::open_cursor(*txn, db::table::kHashedAccounts)};
    auto target_hashed_code{db::open_cursor(*txn, db::table::kHashedCodeHash)};

    Bytes plain_code_key(kAddressLength + db::kIncarnationLength, '\0');  // Only one allocation
    Bytes hashed_code_key(kHashLength + db::kIncarnationLength, '\0');    // Only one allocation

    for (const auto& [address, pair] : changed_addresses) {
        auto& [address_hash, current_encoded_value] = pair;
        if (!current_encoded_value.empty()) {
            // Update HashedAccounts table
            target_hashed_accounts.upsert(db::to_slice(address_hash.bytes), db::to_slice(current_encoded_value));

            // Lookup value in PlainCodeHash for Contract
            auto [incarnation, err]{Account::incarnation_from_encoded_storage(current_encoded_value)};
            rlp::success_or_throw(err);
            if (incarnation) {
                std::memcpy(&plain_code_key[0], address.bytes, kAddressLength);
                std::memcpy(&hashed_code_key[0], address_hash.bytes, kHashLength);
                endian::store_big_u64(&hashed_code_key[kHashLength], incarnation);
                endian::store_big_u64(&plain_code_key[kAddressLength], incarnation);
                auto code_data{source_plaincode.find(db::to_slice(plain_code_key),
                                                     /*throw_notfound=*/false)};
                if (code_data.done && !code_data.value.empty()) {
                    target_hashed_code.upsert(db::to_slice(hashed_code_key), code_data.value);
                } else {
                    (void)target_hashed_code.erase(db::to_slice(hashed_code_key));
                }
            }
        } else {
            (void)target_hashed_accounts.erase(db::to_slice(address_hash.bytes));
        }

        if (++counter == 128) {
            counter = 0;
            current_key_ = to_hex(address.bytes, true);
            if (is_stopping()) {
                loading_ = false;
                return StageResult::kAborted;
            }
        }
    }
    loading_ = false;
    return StageResult::kSuccess;
}

StageResult HashState::write_changes_from_changed_storage(
    db::RWTxn& txn, db::StorageChanges& storage_changes,
    absl::btree_map<evmc::address, evmc::bytes32>& hashed_addresses) {
    size_t counter{0};

    auto target_hashed_storage{db::open_cursor(*txn, db::table::kHashedStorage)};
    loading_ = true;
    current_target_ = std::string(db::table::kHashedStorage.name);
    Bytes hashed_storage_prefix(db::kHashedStoragePrefixLength, '\0');  // One allocation only
    for (const auto& [address, data] : storage_changes) {
        if (++counter == 128) {
            counter = 0;
            current_key_ = to_hex(address, true);
            if (is_stopping()) {
                return StageResult::kAborted;
            }
        }

        std::memcpy(&hashed_storage_prefix[0], hashed_addresses[address].bytes, kHashLength);
        current_key_ = to_hex(address, true);
        for (const auto& [incarnation, data1] : data) {
            endian::store_big_u64(&hashed_storage_prefix[kHashLength], incarnation);
            for (const auto& [location, value] : data1) {
                auto hashed_location{keccak256(location.bytes)};
                db::upsert_storage_value(target_hashed_storage, hashed_storage_prefix, hashed_location.bytes, value);
            }
        }
    }

    loading_ = false;
    return StageResult::kSuccess;
}


std::vector<std::string> HashState::get_log_progress() {
    std::vector<std::string> ret{};
    if (operation_ == OperationType::None) {
        return ret;
    } else if (operation_ != OperationType::Forward) {
        ret.insert(ret.end(), {"op", std::string(magic_enum::enum_name<OperationType>(operation_.load()))});
    }
    ret.insert(ret.end(), {"mode", (incremental_ ? "incr" : "full")});
    if (loading_) {
        if (!incremental_) {
            current_key_ = abridge(collector_->get_load_key(), kAddressLength * 2 + 2);
        }
        ret.insert(ret.end(), {"to", current_target_, "key", current_key_});
    } else {
        ret.insert(ret.end(), {"from", current_source_, "key", current_key_});
    }
    return ret;
}

void HashState::reset_log_progress() {
    operation_ = OperationType::None;
    incremental_ = false;
    loading_ = false;
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
}

}  // namespace silkworm::stagedsync
