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
        log::Info("Begin HashState",
                  {"from", std::to_string(previous_progress), "to", std::to_string(execution_stage_progress)});
    }

    if (previous_progress != 0) {
        log::Info() << "Starting Account Hashing";
        promote_incremental(txn, OperationType::HashAccount);
        log::Info() << "Starting Storage Hashing";
        promote_incremental(txn, OperationType::HashStorage);
        log::Info() << "Hashing Code Keys";
        promote_incremental(txn, OperationType::Code);
    } else {
        promote_clean_state(txn);
        promote_clean_code(txn);
    }

    // TODO(Andrea) How can we check all blocks have been processed ?

    // Update progress height with last processed block
    db::stages::write_stage_progress(*txn, db::stages::kHashStateKey, execution_stage_progress);
    txn.commit();

    log::Info() << "All Done!";
    return StageResult::kSuccess;
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
        demote_incremental(txn, to, OperationType::HashAccount);

        log::Info() << "[2/3] Hashed storage ... ";
        demote_incremental(txn, to, OperationType::HashStorage);

        log::Info() << "[3/3] Code ... ";
        demote_incremental(txn, to, OperationType::Code);

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
    return StageResult::kUnknownError;
}

void HashState::promote_clean_state(db::RWTxn& txn) {
    // TODO(Andrea) Maybe introduce an assertion for target tables to be empty ?
    etl::Collector account_collector(node_settings_->data_directory->etl().path(), node_settings_->etl_buffer_size);
    etl::Collector storage_collector(node_settings_->data_directory->etl().path(), node_settings_->etl_buffer_size);

    auto source{db::open_cursor(*txn, db::table::kPlainState)};
    auto data{source.to_first(/*throw_notfound=*/false)};
    int percent{0};
    uint8_t next_start_byte{0};
    while (data) {
        if (data.key.at(0) >= next_start_byte) {
            log::Info() << "Progress: " << percent << "%";
            percent += 10;
            next_start_byte += 25;
        }

        // Account
        if (data.key.length() == kAddressLength) {
            auto hash{keccak256(db::from_slice(data.key))};
            etl::Entry entry{Bytes(hash.bytes, kHashLength), Bytes{db::from_slice(data.value)}};
            account_collector.collect(std::move(entry));
        } else {
            SILKWORM_ASSERT(data.key.length() ==
                            db::kPlainStoragePrefixLength);  // plain state key = address + incarnation
            SILKWORM_ASSERT(data.value.length() >
                            kHashLength);  // plain state value = unhashed location + zeroless value

            Bytes new_key(kHashLength * 2 + db::kIncarnationLength, '\0');

            size_t new_key_pos{0};
            std::memcpy(&new_key[new_key_pos], keccak256(db::from_slice(data.key).substr(0, kAddressLength)).bytes,
                        kHashLength);
            data.key.remove_prefix(kAddressLength);
            new_key_pos += kHashLength;

            std::memcpy(&new_key[new_key_pos], data.key.data(), db::kIncarnationLength);
            new_key_pos += db::kIncarnationLength;

            std::memcpy(&new_key[new_key_pos], keccak256(db::from_slice(data.value).substr(0, kHashLength)).bytes,
                        kHashLength);
            data.value.remove_prefix(kHashLength);

            etl::Entry entry{new_key, Bytes{db::from_slice(data.value)}};
            storage_collector.collect(std::move(entry));
        }

        data = source.to_next(/*throw_notfound=*/false);
    }

    if (!account_collector.empty()) {
        auto target{db::open_cursor(*txn, db::table::kHashedAccounts)};
        account_collector.load(target, nullptr, MDBX_put_flags_t::MDBX_APPEND);
    }
    if (!storage_collector.empty()) {
        auto target = db::open_cursor(*txn, db::table::kHashedStorage);

        // ETL key contains hashed location; for DB put we need to move it from key to value
        auto load_func = [](const etl::Entry& entry, mdbx::cursor& cursor, MDBX_put_flags_t flags) -> void {
            assert(entry.key.length() == db::kHashedStoragePrefixLength + kHashLength);
            Bytes value(kHashLength + entry.value.length(), '\0');
            std::memcpy(&value[0], &entry.key[db::kHashedStoragePrefixLength], kHashLength);
            std::memcpy(&value[kHashLength], entry.value.data(), entry.value.length());

            mdbx::slice k{entry.key.data(), db::kHashedStoragePrefixLength};
            mdbx::slice v{db::to_slice(value)};
            mdbx::error::success_or_throw(cursor.put(k, &v, flags));
        };

        storage_collector.load(target, load_func, MDBX_put_flags_t::MDBX_APPENDDUP);
    }
}

void HashState::promote_clean_code(db::RWTxn& txn) {
    // TODO(Andrea) Maybe introduce an assertion for target table to be empty ?
    etl::Collector collector(node_settings_->data_directory->etl().path(), node_settings_->etl_buffer_size);

    auto source{db::open_cursor(*txn, db::table::kPlainContractCode)};
    auto data{source.to_first(/*throw_notfound=*/false)};
    while (data) {
        Bytes new_key(kHashLength + db::kIncarnationLength, '\0');
        std::memcpy(&new_key[0], keccak256(db::from_slice(data.key.safe_middle(0, kAddressLength))).bytes, kHashLength);
        std::memcpy(&new_key[kHashLength], data.key.safe_middle(kAddressLength, db::kIncarnationLength).data(),
                    db::kIncarnationLength);
        etl::Entry entry{new_key, Bytes{db::from_slice(data.value)}};
        collector.collect(std::move(entry));
        data = source.to_next(/*throw_notfound=*/false);
    }
    source.close();
    if (!collector.empty()) {
        source = db::open_cursor(*txn, db::table::kContractCode);
        collector.load(source, nullptr, MDBX_put_flags_t::MDBX_APPEND);
    }
}

void HashState::promote_incremental(db::RWTxn& txn, OperationType operation) {
    auto [changeset_config, target_config] = HashState::get_operation_tables(operation);

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

        if (operation == OperationType::HashAccount) {
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

        } else if (operation == OperationType::HashStorage) {
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

void HashState::demote_incremental(db::RWTxn& txn, BlockNum to, OperationType operation) {
    auto [changeset_config, target_config] = get_operation_tables(operation);

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
    switch (operation) {
        case OperationType::HashAccount:
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
        case OperationType::HashStorage:
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
        case OperationType::Code:
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
            std::string error{magic_enum::enum_name<OperationType>(operation)};
            error.append(": unimplemented operation");
            throw std::runtime_error(error);
    }

    (void)db::cursor_for_each(changeset_table, unwind_func);
}

std::pair<db::MapConfig, db::MapConfig> HashState::get_operation_tables(OperationType operation) {
    switch (operation) {
        case OperationType::HashAccount:
            return {db::table::kAccountChangeSet, db::table::kHashedAccounts};
        case OperationType::HashStorage:
            return {db::table::kStorageChangeSet, db::table::kHashedStorage};
        case OperationType::Code:
            return {db::table::kAccountChangeSet, db::table::kContractCode};
        default:
            std::string error{magic_enum::enum_name<OperationType>(operation)};
            error.append(": unimplemented operation");
            throw std::runtime_error(error);
    }
}

std::vector<std::string> HashState::get_log_progress() {
    // TODO(Andrea) find a reasonable way to log progress
    return {};
}

}  // namespace silkworm::stagedsync
