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

#include "stage_hashstate.hpp"

#include <stdexcept>

#include <magic_enum.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/node/db/access_layer.hpp>

namespace silkworm::stagedsync {

Stage::Result HashState::forward(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::Forward;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        auto execution_stage_progress{db::stages::read_stage_progress(txn, db::stages::kExecutionKey)};
        if (previous_progress == execution_stage_progress) {
            // Nothing to process
            return ret;
        } else if (previous_progress > execution_stage_progress) {
            // Something bad had happened. Not possible execution stage is ahead of bodies
            // Maybe we need to unwind ?
            std::string what{std::string(stage_name_) + " progress " + std::to_string(previous_progress) +
                             " while " + std::string(db::stages::kExecutionKey) + " stage " +
                             std::to_string(execution_stage_progress)};
            throw StageError(Stage::Result::kInvalidProgress, what);
        }
        const BlockNum segment_width{execution_stage_progress - previous_progress};
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(previous_progress),
                       "to", std::to_string(execution_stage_progress),
                       "span", std::to_string(segment_width)});
        }

        reset_log_progress();

        if (!previous_progress || segment_width > db::stages::kLargeBlockSegmentWorthRegen) {
            // Clear any previous contents
            log::Info(log_prefix_, {"clearing", db::table::kHashedAccounts.name});
            txn->clear_map(db::table::kHashedAccounts.name);
            log::Info(log_prefix_, {"clearing", db::table::kHashedStorage.name});
            txn->clear_map(db::table::kHashedStorage.name);
            log::Info(log_prefix_, {"clearing", db::table::kHashedCodeHash.name});
            txn->clear_map(db::table::kHashedCodeHash.name);
            txn.commit_and_renew();

            success_or_throw(hash_from_plainstate(txn));
            collector_->clear();
            reset_log_progress();

            success_or_throw(hash_from_plaincode(txn));
            collector_->clear();
            reset_log_progress();

        } else {
            success_or_throw(hash_from_account_changeset(txn, previous_progress, execution_stage_progress));
            reset_log_progress();

            success_or_throw(hash_from_storage_changeset(txn, previous_progress, execution_stage_progress));
            reset_log_progress();
        }

        throw_if_stopping();
        db::stages::write_stage_progress(txn, db::stages::kHashStateKey, execution_stage_progress);
        txn.commit_and_renew();

    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    reset_log_progress();
    operation_ = OperationType::None;
    collector_.reset();
    return ret;
}

Stage::Result HashState::unwind(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    if (!sync_context_->unwind_point.has_value()) return ret;
    const BlockNum to{sync_context_->unwind_point.value()};

    operation_ = OperationType::Unwind;
    try {
        throw_if_stopping();
        auto previous_progress{db::stages::read_stage_progress(txn, stage_name_)};
        if (to >= previous_progress) {
            // Nothing to unwind actually
            return ret;
        }
        const BlockNum segment_width{previous_progress - to};
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(previous_progress),
                       "to", std::to_string(to),
                       "span", std::to_string(segment_width)});
        }

        success_or_throw(unwind_from_account_changeset(txn, previous_progress, to));
        reset_log_progress();

        success_or_throw(unwind_from_storage_changeset(txn, previous_progress, to));
        reset_log_progress();

        throw_if_stopping();
        update_progress(txn, to);
        txn.commit_and_renew();

    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return ret;
}

Stage::Result HashState::prune(db::RWTxn&) {
    // HashState does not prune
    return Stage::Result::kSuccess;
}

Stage::Result HashState::hash_from_plainstate(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    try {
        auto source = txn.ro_cursor_dup_sort(db::table::kPlainState);
        auto data{source->to_first(/*throw_notfound=*/true)};

        /*
         * This relies on the assumption previous execution stage has completed correctly,
         * and we do nothing more than hashing keys already present in PlainState either
         * to HashedAccount or to HashedStorage. We don't need to check an upper block
         * limit as PlainState holds info up to the highest executed block.
         */

        evmc::address last_address{};
        ethash_hash256 address_hash{keccak256(last_address.bytes)};  // We might have all zeroed addresses ?

        std::unique_lock log_lck(log_mtx_);
        current_source_ = std::string(db::table::kPlainState.name);
        current_key_ = to_hex(last_address.bytes, /*with_prefix=*/true);
        log_lck.unlock();

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
                throw_if_stopping();
                last_address = bytes_to_address(data_key_view);
                address_hash = keccak256(last_address.bytes);
                log_lck.lock();
                current_key_ = to_hex(last_address.bytes, /*with_prefix=*/true);
                log_lck.unlock();
            }

            if (data.key.length() == kAddressLength) {
                // Hash account
                // data.key == Address
                // data.value == Account encoded for storage (must exist)
                if (!data.value.length()) {
                    const std::string what("Unexpected empty value in PlainState for Account " + current_key_);
                    throw StageError(Stage::Result::kUnexpectedError, what);
                }

                etl::Entry entry{Bytes(address_hash.bytes, kHashLength), Bytes{db::from_slice(data.value)}};
                collector_->collect(std::move(entry));

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
                        throw StageError(Stage::Result::kUnexpectedError, what);
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
                    data = source->to_current_next_multi(false);
                }

            } else {
                std::string what{"Unexpected key length " + std::to_string(data.key.length())};
                throw StageError(Stage::Result::kUnexpectedError, what);
            }

            data = source->to_next(/*throw_notfound=*/false);
        }

        throw_if_stopping();

        if (!collector_->empty()) {
            auto account_target = txn.rw_cursor_dup_sort(db::table::kHashedAccounts);  // note: not a multi-value table
            auto storage_target = txn.rw_cursor_dup_sort(db::table::kHashedStorage);

            if (!account_target->empty())
                throw std::runtime_error(std::string(db::table::kHashedAccounts.name) + " should be empty");
            if (!storage_target->empty())
                throw std::runtime_error(std::string(db::table::kHashedStorage.name) + " should be empty");

            // ETL key contains hashed location; for DB put we need to move it from key to value
            const etl::LoadFunc load_func = [&storage_target](const etl::Entry& entry, db::RWCursorDupSort& target,
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
                    mdbx::error::success_or_throw(storage_target->put(k, &v, MDBX_APPENDDUP));
                } else {
                    std::string what{"Unexpected key length " + std::to_string(entry.key.length()) + " in PlainState"};
                    throw StageError(Stage::Result::kUnexpectedError, what);
                }
            };

            log_lck.lock();
            current_target_ =
                std::string(db::table::kHashedAccounts.name) + "+" + std::string(db::table::kHashedStorage.name);
            loading_ = true;
            log_lck.unlock();
            collector_->load(*account_target, load_func, MDBX_put_flags_t::MDBX_APPENDDUP);
        }

    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    return ret;
}

Stage::Result HashState::hash_from_plaincode(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    try {
        auto source = txn.ro_cursor(db::table::kPlainCodeHash);
        auto data{source->to_first(/*throw_notfound=*/false)};

        evmc::address last_address{};
        Bytes new_key(db::kHashedStoragePrefixLength, '\0');

        std::unique_lock log_lck(log_mtx_);
        current_source_ = std::string(db::table::kPlainCodeHash.name);
        current_key_ = to_hex(last_address.bytes, /*with_prefix=*/true);
        log_lck.unlock();

        while (data) {
            if (data.key.length() != kAddressLength + db::kIncarnationLength) {
                std::string what{"Unexpected key len " + std::to_string(data.key.length())};
                throw StageError(Stage::Result::kUnexpectedError, what);
            }

            auto data_key_view{db::from_slice(data.key)};

            // We're reading PlainCodeHash which keys are ordered by address (always initial 20 bytes of key)
            // Rehash the address only when changes
            if (std::memcmp(data_key_view.data(), last_address.bytes, kAddressLength) != 0) {
                throw_if_stopping();
                last_address = bytes_to_address(data_key_view);
                log_lck.lock();
                current_key_ = to_hex(last_address.bytes, /*with_prefix=*/true);
                log_lck.unlock();

                const auto address_hash{keccak256(last_address.bytes)};
                std::memcpy(&new_key[0], address_hash.bytes, kHashLength);
            }

            std::memcpy(&new_key[kHashLength], &data_key_view[kAddressLength], db::kIncarnationLength);

            etl::Entry entry{new_key, Bytes{db::from_slice(data.value)}};
            collector_->collect(std::move(entry));
            data = source->to_next(/*throw_notfound=*/false);
        }

        throw_if_stopping();

        if (!collector_->empty()) {
            auto target = txn.rw_cursor_dup_sort(db::table::kHashedCodeHash);  // note: not a multi-value table
            if (!target->empty())
                throw std::runtime_error(std::string(db::table::kHashedCodeHash.name) + " should be empty");

            log_lck.lock();
            current_target_ = std::string(db::table::kHashedCodeHash.name);
            loading_ = true;
            log_lck.unlock();
            collector_->load(*target, nullptr, MDBX_put_flags_t::MDBX_APPEND);
        }

    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    return ret;
}

Stage::Result HashState::hash_from_account_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to) {
    Stage::Result ret{Stage::Result::kSuccess};
    try {
        /*
         * 1) Read AccountChangeSet from previous_progress to 'to'
         * 2) For each address changed hash it and lookup current value from PlainState
         * 3) Process the collected list and write values into Hashed tables (Account and Code)
         */

        BlockNum reached_blocknum{0};
        BlockNum expected_blocknum{previous_progress + 1};
        ChangedAddresses changed_addresses{};

        std::unique_lock log_lck(log_mtx_);
        operation_ = OperationType::Forward;
        incremental_ = true;
        current_source_ = std::string(db::table::kAccountChangeSet.name);
        current_key_ = std::to_string(expected_blocknum);
        log_lck.unlock();

        auto source_initial_key{db::block_key(expected_blocknum)};
        auto source_changeset = txn.ro_cursor_dup_sort(db::table::kAccountChangeSet);
        auto source_plainstate = txn.ro_cursor_dup_sort(db::table::kPlainState);
        auto changeset_data{
            source_changeset->find(db::to_slice(source_initial_key),  // Initial record MUST be found because
                                   /*throw_notfound=*/true)};         // there is at least 1 change per block
                                                                      // (the miner reward)
        while (changeset_data.done) {
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
                evmc::address address{bytes_to_address(changeset_value_view)};
                if (!changed_addresses.contains(address)) {
                    auto address_hash{to_bytes32(keccak256(address.bytes).bytes)};
                    auto plainstate_data{source_plainstate->find(db::to_slice(address), /*throw_notfound=*/false)};
                    if (plainstate_data.done) {
                        Bytes current_value{db::from_slice(plainstate_data.value)};
                        changed_addresses[address] = std::make_pair(address_hash, current_value);
                    } else {
                        changed_addresses[address] = std::make_pair(address_hash, Bytes());
                    }
                }
                changeset_data = source_changeset->to_current_next_multi(/*throw_notfound=*/false);
            }
            ++expected_blocknum;
            changeset_data = source_changeset->to_next(/*throw_notfound=*/false);
        }

        ret = write_changes_from_changed_addresses(txn, changed_addresses);

    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    return ret;
}

Stage::Result HashState::hash_from_storage_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to) {
    Stage::Result ret{Stage::Result::kSuccess};
    try {
        /*
         * 1) Read StorageChangeSet from previous_progress to 'to'
         * 2) For each address + incarnation changed hash it and lookup current value from PlainState
         * 3) Process the collected list and write values into HashedStorage
         */

        BlockNum reached_blocknum{0};

        db::StorageChanges storage_changes{};
        absl::btree_map<evmc::address, evmc::bytes32> hashed_addresses{};

        std::unique_lock log_lck(log_mtx_);
        operation_ = OperationType::Forward;
        incremental_ = true;
        current_source_ = std::string(db::table::kStorageChangeSet.name);
        current_key_ = std::to_string(previous_progress + 1);
        log_lck.unlock();

        auto source_changeset = txn.ro_cursor_dup_sort(db::table::kStorageChangeSet);
        auto source_plainstate = txn.ro_cursor_dup_sort(db::table::kPlainState);

        // find fist block with changes
        BlockNum initial_block{previous_progress + 1};
        auto source_initial_key{db::block_key(initial_block)};
        auto changeset_data = source_changeset->lower_bound(db::to_slice(source_initial_key), /*throw_notfound=*/false);
        while (!changeset_data.done && initial_block <= to) {
            ++initial_block;
            source_initial_key = db::block_key(initial_block);
            changeset_data = source_changeset->lower_bound(db::to_slice(source_initial_key), /*throw_notfound=*/false);
        }

        // process changes
        while (changeset_data.done) {
            auto changeset_key_view{db::from_slice(changeset_data.key)};
            reached_blocknum = endian::load_big_u64(changeset_key_view.data());
            if (reached_blocknum > to) {
                break;
            }

            if (reached_blocknum % 32 == 0) {
                throw_if_stopping();
                log_lck.lock();
                current_key_ = std::to_string(reached_blocknum);
                log_lck.unlock();
            }

            changeset_key_view.remove_prefix(8);
            evmc::address address{bytes_to_address(changeset_key_view)};
            changeset_key_view.remove_prefix(kAddressLength);

            const auto incarnation{endian::load_big_u64(changeset_key_view.data())};
            if (!incarnation) {
                throw StageError(Stage::Result::kUnexpectedError, "Unexpected EOA in StorageChangeset");
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
                    auto plain_state_value{db::find_value_suffix(*source_plainstate, plain_storage_prefix, location.bytes)};
                    storage_changes[address][incarnation].insert_or_assign(location,
                                                                           plain_state_value.value_or(Bytes()));
                }
                changeset_data = source_changeset->to_current_next_multi(/*throw_notfound=*/false);
            }
            changeset_data = source_changeset->to_next(/*throw_notfound=*/false);
        }

        ret = write_changes_from_changed_storage(txn, storage_changes, hashed_addresses);

    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    return ret;
}

Stage::Result HashState::unwind_from_account_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to) {
    Stage::Result ret{Stage::Result::kSuccess};
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

        std::unique_lock log_lck(log_mtx_);
        operation_ = OperationType::Unwind;
        current_source_ = std::string(db::table::kAccountChangeSet.name);
        current_key_ = std::to_string(expected_blocknum);
        log_lck.unlock();

        throw_if_stopping();

        auto changeset_cursor = txn.ro_cursor_dup_sort(db::table::kAccountChangeSet);
        auto initial_key{db::block_key(expected_blocknum)};
        auto changeset_data{changeset_cursor->find(db::to_slice(initial_key), /*throw_notfound=*/true)};

        while (changeset_data.done) {
            reached_blocknum = endian::load_big_u64(db::from_slice(changeset_data.key).data());
            check_block_sequence(reached_blocknum, expected_blocknum);
            if (reached_blocknum > previous_progress) {
                break;
            }

            if (reached_blocknum % 32 == 0) {
                throw_if_stopping();
                log_lck.lock();
                current_key_ = std::to_string(reached_blocknum);
                log_lck.unlock();
            }

            while (changeset_data.done) {
                auto changeset_value_view{db::from_slice(changeset_data.value)};
                ensure(changeset_value_view.length() >= kAddressLength,
                       "invalid account changeset value size=" + std::to_string(changeset_value_view.length()) +
                           " at block " + std::to_string(reached_blocknum));
                evmc::address address{bytes_to_address(changeset_value_view)};

                if (!changed_addresses.contains(address)) {
                    changeset_value_view.remove_prefix(kAddressLength);
                    auto address_hash{to_bytes32(keccak256(address.bytes).bytes)};
                    Bytes previous_value(changeset_value_view.data(), changeset_value_view.length());
                    changed_addresses[address] = std::make_pair(address_hash, previous_value);
                }
                changeset_data = changeset_cursor->to_current_next_multi(/*throw_notfound=*/false);
            }

            ++expected_blocknum;
            changeset_data = changeset_cursor->to_next(/*throw_notfound=*/false);
        }

        ret = write_changes_from_changed_addresses(txn, changed_addresses);

    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return Stage::Result::kDbError;
    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return Stage::Result::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "undefined"});
        return Stage::Result::kUnexpectedError;
    }

    return ret;
}

Stage::Result HashState::unwind_from_storage_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to) {
    Stage::Result ret{Stage::Result::kSuccess};

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

        std::unique_lock log_lck(log_mtx_);
        operation_ = OperationType::Unwind;
        incremental_ = true;
        current_source_ = std::string(db::table::kStorageChangeSet.name);
        current_key_ = std::to_string(to + 1);
        log_lck.unlock();

        auto changeset_cursor = txn.ro_cursor_dup_sort(db::table::kStorageChangeSet);
        auto initial_key_prefix{db::block_key(to + 1)};
        auto changeset_data{changeset_cursor->lower_bound(db::to_slice(initial_key_prefix), /*throw_notfound=*/true)};

        while (changeset_data.done) {
            auto changeset_key_view{db::from_slice(changeset_data.key)};
            ensure(changeset_key_view.length() == sizeof(BlockNum) + db::kPlainStoragePrefixLength,
                   "invalid storage changeset key size=" + std::to_string(changeset_key_view.length()));
            reached_blocknum = endian::load_big_u64(changeset_key_view.data());
            if (reached_blocknum > previous_progress) {
                break;
            }

            if (reached_blocknum % 32 == 0) {
                throw_if_stopping();
                log_lck.lock();
                current_key_ = std::to_string(reached_blocknum);
                log_lck.unlock();
            }

            changeset_key_view.remove_prefix(sizeof(BlockNum));
            evmc::address address{bytes_to_address(changeset_key_view)};
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
                ensure(changeset_value_view.length() >= kHashLength,
                       "invalid storage changeset value size=" + std::to_string(changeset_value_view.length()) +
                           " at block " + std::to_string(reached_blocknum));
                auto location{to_bytes32(changeset_value_view)};
                if (!storage_changes[address][incarnation].contains(location)) {
                    changeset_value_view.remove_prefix(kHashLength);
                    Bytes previous_value{changeset_value_view};
                    storage_changes[address][incarnation].insert_or_assign(location, previous_value);
                }
                changeset_data = changeset_cursor->to_current_next_multi(/*throw_notfound=*/false);
            }
            changeset_data = changeset_cursor->to_next(/*throw_notfound=*/false);
        }

        ret = write_changes_from_changed_storage(txn, storage_changes, hashed_addresses);

    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    return ret;
}

Stage::Result HashState::write_changes_from_changed_addresses(db::RWTxn& txn, const ChangedAddresses& changed_addresses) {
    throw_if_stopping();

    std::unique_lock log_lck(log_mtx_);
    current_target_ = std::string(db::table::kHashedAccounts.name) + " " + std::string(db::table::kHashedCodeHash.name);
    loading_ = true;
    current_key_ = to_hex(changed_addresses.begin()->first.bytes, /*with_prefix=*/true);
    log_lck.unlock();

    auto source_plaincode = txn.ro_cursor(db::table::kPlainCodeHash);
    auto target_hashed_accounts = txn.rw_cursor(db::table::kHashedAccounts);
    auto target_hashed_code = txn.rw_cursor(db::table::kHashedCodeHash);

    Bytes plain_code_key(kAddressLength + db::kIncarnationLength, '\0');  // Only one allocation
    Bytes hashed_code_key(kHashLength + db::kIncarnationLength, '\0');    // Only one allocation

    evmc::address last_address{};

    for (const auto& [address, pair] : changed_addresses) {
        if (address != last_address) {
            throw_if_stopping();
            last_address = address;
            log_lck.lock();
            current_key_ = address_to_hex(address);
            log_lck.unlock();
        }

        auto& [address_hash, current_encoded_value] = pair;
        if (!current_encoded_value.empty()) {
            // Update HashedAccounts table
            target_hashed_accounts->upsert(db::to_slice(address_hash), db::to_slice(current_encoded_value));

            // Lookup value in PlainCodeHash for Contract
            const auto incarnation{Account::incarnation_from_encoded_storage(current_encoded_value)};
            success_or_throw(incarnation);
            if (incarnation != 0) {
                std::memcpy(&plain_code_key[0], address.bytes, kAddressLength);
                std::memcpy(&hashed_code_key[0], address_hash.bytes, kHashLength);
                endian::store_big_u64(&hashed_code_key[kHashLength], *incarnation);
                endian::store_big_u64(&plain_code_key[kAddressLength], *incarnation);
                auto code_data{source_plaincode->find(db::to_slice(plain_code_key),
                                                      /*throw_notfound=*/false)};
                if (code_data.done && !code_data.value.empty()) {
                    target_hashed_code->upsert(db::to_slice(hashed_code_key), code_data.value);
                } else {
                    target_hashed_code->erase(db::to_slice(hashed_code_key));
                }
            }
        } else {
            target_hashed_accounts->erase(db::to_slice(address_hash));
        }
    }

    return Stage::Result::kSuccess;
}

Stage::Result HashState::write_changes_from_changed_storage(
    db::RWTxn& txn, db::StorageChanges& storage_changes,
    const absl::btree_map<evmc::address, evmc::bytes32>& hashed_addresses) {
    throw_if_stopping();
    auto target_hashed_storage = txn.rw_cursor_dup_sort(db::table::kHashedStorage);

    std::unique_lock log_lck(log_mtx_);
    loading_ = true;
    current_target_ = std::string(db::table::kHashedStorage.name);
    log_lck.unlock();

    evmc::address last_address{};
    Bytes hashed_storage_prefix(db::kHashedStoragePrefixLength, '\0');  // One allocation only
    for (const auto& [address, data] : storage_changes) {
        if (address != last_address) {
            throw_if_stopping();
            last_address = address;
            std::memcpy(&hashed_storage_prefix[0], hashed_addresses.at(last_address).bytes, kHashLength);

            log_lck.lock();
            current_key_ = address_to_hex(address);
            log_lck.unlock();
        }

        for (const auto& [incarnation, data1] : data) {
            endian::store_big_u64(&hashed_storage_prefix[kHashLength], incarnation);
            for (const auto& [location, value] : data1) {
                auto hashed_location{keccak256(location.bytes)};
                db::upsert_storage_value(*target_hashed_storage, hashed_storage_prefix, hashed_location.bytes, value);
            }
        }
    }

    return Stage::Result::kSuccess;
}

std::vector<std::string> HashState::get_log_progress() {
    std::unique_lock log_lck(log_mtx_);
    std::vector<std::string> ret{"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                                 "mode", (incremental_ ? "incr" : "full")};
    if (operation_ == OperationType::None) {
        return ret;
    }
    if (loading_) {
        if (!incremental_ && !collector_->get_load_key().empty()) {
            current_key_ = abridge(collector_->get_load_key(), kAddressLength * 2 + 2);
        }
        ret.insert(ret.end(), {"to", current_target_, "key", current_key_});
    } else {
        ret.insert(ret.end(), {"from", current_source_, "key", current_key_});
    }
    return ret;
}

void HashState::reset_log_progress() {
    std::unique_lock log_lck(log_mtx_);
    incremental_ = false;
    loading_ = false;
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
}

}  // namespace silkworm::stagedsync
