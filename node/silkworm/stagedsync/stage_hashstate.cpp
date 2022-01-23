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

#include <silkworm/common/assert.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
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

    try {
        if (!previous_progress) {
            log::Info("Promoting clean state",
                      {"from", std::to_string(previous_progress), "to", std::to_string(execution_stage_progress)});
            current_key_.clear();
            current_source_.clear();
            current_target_.clear();
            StageResult result{promote_clean_state(txn)};
            collector_->clear();
            if (result != StageResult::kSuccess) {
                return result;
            }
            current_key_.clear();
            current_source_.clear();
            current_target_.clear();
            result = promote_clean_code(txn);
            collector_->clear();
            if (result != StageResult::kSuccess) {
                return result;
            }

        } else {
            if (execution_stage_progress - previous_progress > 16) {
                log::Info("Promoting incremental state",
                          {"from", std::to_string(previous_progress), "to", std::to_string(execution_stage_progress)});
            }
            promote_incremental(txn, DataKind::Account);
            promote_incremental(txn, DataKind::Storage);
            promote_incremental(txn, DataKind::Code);
        }

        // TODO(Andrea) How can we check all blocks have been processed ?
        //        if (!is_stopping()) {
        //            db::stages::write_stage_progress(*txn, db::stages::kHashStateKey, execution_stage_progress);
        //            txn.commit();
        //            return StageResult::kSuccess;
        //        }
        return StageResult::kAborted;

    } catch (const std::exception& ex) {
        log::Error(std::string(stage_name_), {"exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    }
}

StageResult HashState::unwind(db::RWTxn& txn, BlockNum to) {
    try {
        auto stage_height{db::stages::read_stage_progress(*txn, db::stages::kHashStateKey)};
        if (to >= stage_height) {
            log::Error() << "Stage progress is " << stage_height << " which is <= than requested unwind_to";
            return StageResult::kAborted;
        }

        log::Info() << "Unwinding HashState from " << stage_height << " to " << to << " ...";

        log::Info() << "[1/3] Hashed accounts ... ";
        demote_incremental(txn, to, DataKind::Account);

        log::Info() << "[2/3] Hashed storage ... ";
        demote_incremental(txn, to, DataKind::Storage);

        log::Info() << "[3/3] Code ... ";
        demote_incremental(txn, to, DataKind::Code);

        // Update progress height with last processed block
        db::stages::write_stage_progress(*txn, db::stages::kHashStateKey, to);

        log::Info() << "Committing ... ";
        txn.commit();

        log::Info() << "All Done!";
        return StageResult::kSuccess;

    } catch (const std::exception& ex) {
        log::Error() << "Unexpected error : " << ex.what();
        return StageResult::kAborted;
    }
}

StageResult HashState::prune(db::RWTxn& txn) {
    // TODO(Andrea) This is yet to be implemented
    (void)txn;
    return StageResult::kUnknownError;
}

StageResult HashState::promote_clean_state(db::RWTxn& txn) {
    try {
        current_source_ = std::string(db::table::kPlainState.name);
        auto source{db::open_cursor(*txn, db::table::kPlainState)};
        auto data{source.to_first(/*throw_notfound=*/false)};
        if (!data.done) {
            // Table empty. Nothing to process
            return is_stopping() ? StageResult::kAborted : StageResult::kSuccess;
        }

        // TODO(Andrea) Maybe introduce an assertion for target tables to be empty ?

        // TODO(Andrea) This is all about hashing. Parallelize !

        /*
         * This relies on the assumption previous execution stage has completed correctly
         * and we do nothing more than hashing keys already present in PlainState either
         * to HashedAccount or to HashedStorage. We don't need to check an upper block
         * limit as we don't have it in PlainState
         */

        // Hash accounts
        current_source_ = "Account+Storage";
        while (data) {
            if (data.key.length() == kAddressLength) {
                // Hash account
                // data.key == Address
                // data.value == Account encoded for storage
                const auto data_key_view{db::from_slice(data.key)};
                auto hash{keccak256(data_key_view)};
                etl::Entry entry{Bytes(hash.bytes, kHashLength), Bytes{db::from_slice(data.value)}};
                collector_->collect(std::move(entry));
                if (collector_->size() % 64 == 0) {
                    current_key_ = abridge(to_hex(data_key_view, /*with_prefix=*/true), kAddressLength * 2 + 2);
                    if (is_stopping()) {
                        return StageResult::kAborted;
                    }
                }
            } else if (data.key.length() == db::kPlainStoragePrefixLength) {
                // Hash storage
                // data.key           == Address + Incarnation
                // data.value (multi) == Location + zeroless Value

                // New Hashed Storage Key
                // + Address hash
                // + Incarnation
                // + Location hash

                auto data_key_view{db::from_slice(data.key)};
                Bytes new_key(kHashLength * 2 + db::kIncarnationLength, '\0');
                std::memcpy(&new_key[0], keccak256(data_key_view.substr(0, kAddressLength)).bytes, kHashLength);
                data_key_view.remove_prefix(kAddressLength);
                std::memcpy(&new_key[kHashLength], data_key_view.data(), db::kIncarnationLength);

                // Iterate dupkeys only to avoid re-hashing of same address
                while (data) {
                    SILKWORM_ASSERT(data.value.length() >
                                    kHashLength);  // plain state value = unhashed location + zeroless value

                    /*
                     * NOTE !
                     * Destination table kHashedStorage is dup-sorted but as Collector implements sorting only on entry
                     * key here we have to build the entry key as hashed address + incarnation + hashed storage location
                     * eventually leaving entry value to only hashed storage value. This ensures entries are collected
                     * and sorted properly and eventually the loader will move back hashed storage location in the value
                     * part of the db record. This way we can reliably insert records using MDBX_APPENDDUP
                     */

                    auto data_value_view{db::from_slice(data.value)};
                    std::memcpy(&new_key[kHashLength + db::kIncarnationLength],
                                keccak256(data_value_view.substr(0, kHashLength)).bytes, kHashLength);
                    data_value_view.remove_prefix(kHashLength);
                    etl::Entry entry{new_key, Bytes{data_value_view}};
                    collector_->collect(std::move(entry));
                    if (collector_->size() % 64 == 0) {
                        current_key_ =
                            abridge(to_hex(db::from_slice(data.key), /*with_prefix=*/true), kAddressLength * 2 + 2);
                        if (is_stopping()) {
                            return StageResult::kAborted;
                        }
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
                    if (entry.key.length() == kHashLength) {
                        mdbx::slice k{db::to_slice(entry.key)};
                        mdbx::slice v{db::to_slice(entry.value)};
                        mdbx::error::success_or_throw(target.put(k, &v, MDBX_APPEND));
                    } else if (entry.key.length() == db::kHashedStoragePrefixLength + kHashLength) {
                        Bytes new_value(kHashLength + entry.value.length(), '\0');
                        std::memcpy(&new_value[0], &entry.key[db::kHashedStoragePrefixLength], kHashLength);
                        std::memcpy(&new_value[kHashLength], entry.value.data(), entry.value.length());
                        mdbx::slice k{entry.key.data(), db::kHashedStoragePrefixLength};
                        mdbx::slice v{db::to_slice(new_value)};
                        mdbx::error::success_or_throw(storage_target.put(k, &v, MDBX_APPENDDUP));
                    } else {
                        std::string what{"Unexpected key length " + std::to_string(entry.key.length())};
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

StageResult HashState::promote_clean_code(db::RWTxn& txn) {
    auto source{db::open_cursor(*txn, db::table::kPlainContractCode)};
    auto data{source.to_first(/*throw_notfound=*/false)};
    if (!data.done) {
        // Table empty. Nothing to process
        return is_stopping() ? StageResult::kAborted : StageResult::kSuccess;
    }

    try {
        // TODO(Andrea) Maybe introduce an assertion for target table to be empty ?
        current_source_ = std::string(db::table::kPlainContractCode.name);
        Bytes new_key(db::kHashedStoragePrefixLength, '\0');

        while (data) {
            if (data.key.length() != kAddressLength + db::kIncarnationLength) {
                std::string what{"Unexpected key len " + std::to_string(data.key.length())};
                throw std::runtime_error(what);
            }

            auto data_key_view{db::from_slice(data.key)};
            std::memcpy(&new_key[kHashLength], &data_key_view[kAddressLength], db::kIncarnationLength);
            data_key_view.remove_suffix(db::kIncarnationLength);
            std::memcpy(&new_key[0], keccak256(data_key_view).bytes, kHashLength);

            etl::Entry entry{new_key, Bytes{db::from_slice(data.value)}};
            collector_->collect(std::move(entry));
            if (collector_->size() % 64 == 0) {
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
                source = db::open_cursor(*txn, db::table::kContractCode);
                current_target_ = std::string(db::table::kContractCode.name);
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

void HashState::promote_incremental(db::RWTxn& txn, DataKind kind) {
    auto [changeset_config, target_config] = HashState::get_operation_tables(kind);

    auto changeset_table{db::open_cursor(*txn, changeset_config)};
    auto plainstate_table{db::open_cursor(*txn, db::table::kPlainState)};
    auto codehash_table{db::open_cursor(*txn, db::table::kPlainContractCode)};
    auto target_table{db::open_cursor(*txn, target_config)};

    auto start_block_number{db::stages::read_stage_progress(*txn, db::stages::kHashStateKey) + 1};

    Bytes start_key{db::block_key(start_block_number)};
    auto changeset_data{changeset_table.lower_bound(db::to_slice(start_key), /*throw_notfound=*/false)};

    while (changeset_data) {
        Bytes mdb_key_as_bytes{db::from_slice(changeset_data.key)};
        Bytes mdb_value_as_bytes{db::from_slice(changeset_data.value)};
        auto [db_key, _]{db::change_set_to_plain_state_format(mdb_key_as_bytes, mdb_value_as_bytes)};

        if (kind == DataKind::Account) {
            // We get account and hash its key.
            auto plainstate_data{plainstate_table.find(db::to_slice(db_key), /*throw_notfound=*/false)};
            if (!plainstate_data) {
                changeset_data = changeset_table.to_next(/*throw_notfound=*/false);
                continue;
            }
            // Hashing
            auto hash{keccak256(db_key)};
            target_table.upsert(db::to_slice(hash.bytes), plainstate_data.value);
            changeset_data = changeset_table.to_next(false);

        } else if (kind == DataKind::Storage) {
            auto plainstate_data{plainstate_table.find(db::to_slice(db_key), /*throw_notfound=*/false)};
            if (!plainstate_data) {
                changeset_data = changeset_table.to_next(/*throw_notfound=*/false);
                continue;
            }

            // plain state key = address + incarnation
            assert(db_key.length() == db::kPlainStoragePrefixLength);

            Bytes hashed_key(db::kHashedStoragePrefixLength, '\0');
            std::memcpy(&hashed_key[0], keccak256(db_key.substr(0, kAddressLength)).bytes, kHashLength);
            std::memcpy(&hashed_key[kHashLength], &db_key[kAddressLength], db::kIncarnationLength);

            // plain state value = unhashed location + zeroless value
            assert(plainstate_data.value.length() > kHashLength);

            auto hashed_location{keccak256(db::from_slice(plainstate_data.value).substr(0, kHashLength))};
            ByteView value{db::from_slice(plainstate_data.value).substr(kHashLength)};

            db::upsert_storage_value(target_table, hashed_key, hashed_location.bytes, value);

            changeset_data = changeset_table.to_next(/*throw_notfound=*/false);

        } else {
            // get incarnation
            auto encoded_account{plainstate_table.find(db::to_slice(db_key), false)};
            if (!encoded_account) {
                changeset_data = changeset_table.to_next(/*throw_notfound=*/false);
                continue;
            }
            auto [incarnation, err]{extract_incarnation(db::from_slice(encoded_account.value))};
            rlp::success_or_throw(err);
            if (incarnation == 0) {
                changeset_data = changeset_table.to_next(/*throw_notfound=*/false);
                continue;
            }

            // get code hash
            Bytes plain_key(kAddressLength + db::kIncarnationLength, '\0');
            std::memcpy(&plain_key[0], &db_key[0], kAddressLength);
            endian::store_big_u64(&plain_key[kAddressLength], incarnation);
            auto code_hash{codehash_table.find(db::to_slice(plain_key), false)};
            if (!code_hash) {
                changeset_data = changeset_table.to_next(/*throw_notfound=*/false);
                continue;
            }

            // Hash and concatenate everything together
            Bytes key(kHashLength + db::kIncarnationLength, '\0');
            std::memcpy(&key[0], keccak256(plain_key.substr(0, kAddressLength)).bytes, kHashLength);
            std::memcpy(&key[kHashLength], &plain_key[kAddressLength], db::kIncarnationLength);
            target_table.upsert(db::to_slice(key), code_hash.value);
            changeset_data = changeset_table.to_next(/*throw_notfound=*/false);
        }
    }
}

void HashState::demote_incremental(db::RWTxn& txn, BlockNum to, DataKind kind) {
    auto [changeset_config, target_config] = get_operation_tables(kind);

    auto changeset_table{db::open_cursor(*txn, changeset_config)};
    auto target_table{db::open_cursor(*txn, target_config)};
    auto code_table{db::open_cursor(*txn, db::table::kContractCode)};
    auto contract_code_table{db::open_cursor(*txn, db::table::kPlainContractCode)};

    Bytes start_key{db::block_key(to + 1)};
    auto changeset_data{changeset_table.lower_bound(db::to_slice(start_key), /*throw_notfound=*/false)};
    if (!changeset_data) {
        return;
    }

    db::WalkFunc unwind_func;
    switch (kind) {
        case DataKind::Account:
            unwind_func = [&target_table, &code_table](const ::mdbx::cursor&,
                                                       const ::mdbx::cursor::move_result& data) -> bool {
                auto [db_key, db_value]{
                    db::change_set_to_plain_state_format(db::from_slice(data.key), db::from_slice(data.value))};

                auto hash{keccak256(db_key)};
                auto new_key{db::to_slice(hash.bytes)};
                if (db_value.empty()) {
                    target_table.erase(new_key);
                    return true;
                }
                auto [acc, err]{decode_account_from_storage(db_value)};
                rlp::success_or_throw(err);

                if (acc.incarnation <= 0 || acc.code_hash != kEmptyHash) {
                    target_table.upsert(new_key, db::to_slice(db_value));
                    return true;
                }

                Bytes code_key(kHashLength + db::kIncarnationLength, '\0');
                std::memcpy(&code_key[0], hash.bytes, kHashLength);
                std::memcpy(&code_key[kHashLength], db::block_key(acc.incarnation).data(), db::kIncarnationLength);

                auto code_hash_data{code_table.find(db::to_slice(code_key), false)};

                if (code_hash_data) {
                    std::memcpy(acc.code_hash.bytes, code_hash_data.value.data(), kHashLength);
                }

                auto new_value(acc.encode_for_storage());
                target_table.upsert(new_key, db::to_slice(new_value));
                return true;
            };
            break;
        case DataKind::Storage:
            unwind_func = [&target_table](const ::mdbx::cursor&, const ::mdbx::cursor::move_result& data) -> bool {
                auto [db_key, db_value]{
                    db::change_set_to_plain_state_format(db::from_slice(data.key), db::from_slice(data.value))};

                Bytes hashed_key(db::kHashedStoragePrefixLength, '\0');
                std::memcpy(&hashed_key[0], keccak256(db_key.substr(0, kAddressLength)).bytes, kHashLength);
                std::memcpy(&hashed_key[kHashLength], &db_key[kAddressLength], db::kIncarnationLength);

                auto hashed_location{keccak256(db_key.substr(db::kPlainStoragePrefixLength))};

                db::upsert_storage_value(target_table, hashed_key, hashed_location.bytes, db_value);

                return true;
            };
            break;
        case DataKind::Code:
            unwind_func = [&target_table, &contract_code_table](const ::mdbx::cursor&,
                                                                const ::mdbx::cursor::move_result& data) -> bool {
                auto [db_key, db_value]{
                    db::change_set_to_plain_state_format(db::from_slice(data.key), db::from_slice(data.value))};
                if (db_value.empty()) {
                    return true;
                }
                auto [incarnation, err]{extract_incarnation(db_value)};
                rlp::success_or_throw(err);
                if (incarnation == 0) {
                    return true;
                }
                // Get incarnation
                auto plain_storage_key{db::storage_prefix(db_key, incarnation)};
                auto code_hash_data{contract_code_table.find(db::to_slice(plain_storage_key))};

                auto address_hash{keccak256(db_key)};
                Bytes hashed_key(kHashLength + db::kIncarnationLength, '\0');
                std::memcpy(&hashed_key[0], address_hash.bytes, kHashLength);
                std::memcpy(&hashed_key[kHashLength], db::block_key(incarnation).data(), db::kIncarnationLength);
                target_table.upsert(db::to_slice(hashed_key), code_hash_data.value);
                return true;
            };
            break;
        default:
            std::string error{magic_enum::enum_name<DataKind>(kind)};
            error.append(": unimplemented data kind");
            throw std::runtime_error(error);
    }

    (void)db::cursor_for_each(changeset_table, unwind_func);
}

std::pair<db::MapConfig, db::MapConfig> HashState::get_operation_tables(DataKind kind) {
    switch (kind) {
        case DataKind::Account:
            return {db::table::kAccountChangeSet, db::table::kHashedAccounts};
        case DataKind::Storage:
            return {db::table::kStorageChangeSet, db::table::kHashedStorage};
        case DataKind::Code:
            return {db::table::kAccountChangeSet, db::table::kContractCode};
        default:
            std::string error{magic_enum::enum_name<DataKind>(kind)};
            error.append(": unimplemented data kind");
            throw std::runtime_error(error);
    }
}

std::vector<std::string> HashState::get_log_progress() {
    if (!loading_) {
        return {"source", current_source_, "etl", "E+T", "key", current_key_};
    } else {
        std::string key{abridge(collector_->get_load_key(), kAddressLength * 2 + 2)};
        return {"target", current_target_, "etl", "L", "key", key};
    }
}

}  // namespace silkworm::stagedsync
