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

#include <filesystem>

#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/etl/collector.hpp>

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

namespace fs = std::filesystem;

/*
 *  Convert get tables configuration pair for incremental promotion
 *  First configuration of the pair is the source and second configuration is the table to fill.
 */
static std::pair<db::MapConfig, db::MapConfig> get_tables_for_promote(HashstateOperation operation) {
    switch (operation) {
        case HashstateOperation::HashAccount:
            return {db::table::kAccountChangeSet, db::table::kHashedAccounts};
        case HashstateOperation::HashStorage:
            return {db::table::kStorageChangeSet, db::table::kHashedStorage};
        case HashstateOperation::Code:
            return {db::table::kAccountChangeSet, db::table::kContractCode};
        default:
            std::string error{magic_enum::enum_name<HashstateOperation>(operation)};
            error.append(": unknown operation");
            throw std::runtime_error(error);
    }
}

// ETL key contains hashed location; for DB put we need to move it from key to value
static void storage_load(const etl::Entry& entry, mdbx::cursor& cursor, MDBX_put_flags_t flags) {
    assert(entry.key.length() == db::kHashedStoragePrefixLength + kHashLength);

    Bytes value(kHashLength + entry.value.length(), '\0');
    std::memcpy(&value[0], &entry.key[db::kHashedStoragePrefixLength], kHashLength);
    std::memcpy(&value[kHashLength], entry.value.data(), entry.value.length());

    mdbx::slice k{entry.key.data(), db::kHashedStoragePrefixLength};
    mdbx::slice v{db::to_slice(value)};
    mdbx::error::success_or_throw(cursor.put(k, &v, flags));
}

/*
 *  If we haven't done hashstate before(first sync), it is possible to just hash values from plainstates,
 *  This is way faster than using changeset because it uses less database reads.
 */
void hashstate_promote_clean_state(mdbx::txn& txn, const fs::path& etl_path) {
    log::Info() << "Hashing state";

    fs::create_directories(etl_path);
    etl::Collector collector_account(etl_path, 512_Mebi);
    etl::Collector collector_storage(etl_path, 512_Mebi);

    auto src{db::open_cursor(txn, db::table::kPlainState)};
    auto data{src.to_first(/*throw_notfound=*/false)};
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
            collector_account.collect(std::move(entry));
        } else {
            Bytes new_key(kHashLength * 2 + db::kIncarnationLength, '\0');
            size_t new_key_pos{0};

            // plain state key = address + incarnation
            assert(data.key.length() == db::kPlainStoragePrefixLength);

            std::memcpy(&new_key[new_key_pos], keccak256(db::from_slice(data.key).substr(0, kAddressLength)).bytes,
                        kHashLength);
            data.key.remove_prefix(kAddressLength);
            new_key_pos += kHashLength;

            std::memcpy(&new_key[new_key_pos], data.key.data(), db::kIncarnationLength);
            new_key_pos += db::kIncarnationLength;

            // plain state value = unhashed location + zeroless value
            assert(data.value.length() > kHashLength);

            std::memcpy(&new_key[new_key_pos], keccak256(db::from_slice(data.value).substr(0, kHashLength)).bytes,
                        kHashLength);
            data.value.remove_prefix(kHashLength);

            etl::Entry entry{new_key, Bytes{db::from_slice(data.value)}};
            collector_storage.collect(std::move(entry));
        }

        data = src.to_next(/*throw_notfound=*/false);
    }

    log::Info() << "Started Account Loading";
    auto target{db::open_cursor(txn, db::table::kHashedAccounts)};
    collector_account.load(target, nullptr, MDBX_put_flags_t::MDBX_APPEND);

    log::Info() << "Started Storage Loading";
    target = db::open_cursor(txn, db::table::kHashedStorage);
    collector_storage.load(target, storage_load, MDBX_put_flags_t::MDBX_APPENDDUP);
}

void hashstate_promote_clean_code(mdbx::txn& txn, const fs::path& etl_path) {
    log::Info() << "Hashing code keys";

    fs::create_directories(etl_path);
    etl::Collector collector(etl_path, 512_Mebi);

    auto tbl{db::open_cursor(txn, db::table::kPlainContractCode)};
    auto data{tbl.to_first(/*throw_notfound=*/false)};
    while (data) {
        Bytes new_key(kHashLength + db::kIncarnationLength, '\0');
        std::memcpy(&new_key[0], keccak256(db::from_slice(data.key.safe_middle(0, kAddressLength))).bytes, kHashLength);
        std::memcpy(&new_key[kHashLength], data.key.safe_middle(kAddressLength, db::kIncarnationLength).data(),
                    db::kIncarnationLength);
        etl::Entry entry{new_key, Bytes{db::from_slice(data.value)}};
        collector.collect(std::move(entry));
        data = tbl.to_next(/*throw_notfound=*/false);
    }
    tbl.close();

    log::Info() << "Started Code Loading";
    tbl = db::open_cursor(txn, db::table::kContractCode);
    collector.load(tbl, nullptr, MDBX_put_flags_t::MDBX_APPEND);
}

/*
 *  If we have done hashstate before(not first sync),
 *  We need to use changeset because we can use the progress system.
 *  Note: Standard Promotion is way slower than Clean Promotion
 */
void hashstate_promote(mdbx::txn& txn, HashstateOperation operation) {
    auto [changeset_config, target_config] = get_tables_for_promote(operation);

    auto changeset_table{db::open_cursor(txn, changeset_config)};
    auto plainstate_table{db::open_cursor(txn, db::table::kPlainState)};
    auto codehash_table{db::open_cursor(txn, db::table::kPlainContractCode)};
    auto target_table{db::open_cursor(txn, target_config)};

    auto start_block_number{db::stages::read_stage_progress(txn, db::stages::kHashStateKey) + 1};

    Bytes start_key{db::block_key(start_block_number)};
    auto changeset_data{changeset_table.lower_bound(db::to_slice(start_key), /*throw_notfound=*/false)};

    while (changeset_data) {
        Bytes mdb_key_as_bytes{db::from_slice(changeset_data.key)};
        Bytes mdb_value_as_bytes{db::from_slice(changeset_data.value)};
        auto [db_key, _]{db::change_set_to_plain_state_format(mdb_key_as_bytes, mdb_value_as_bytes)};

        if (operation == HashstateOperation::HashAccount) {
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

        } else if (operation == HashstateOperation::HashStorage) {
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
            auto [incarnation, err]{Account::incarnation_from_encoded_storage(db::from_slice(encoded_account.value))};
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

StageResult stage_hashstate(db::RWTxn& txn, const fs::path& etl_path, uint64_t) {
    log::Info() << "Starting HashState";

    auto last_processed_block_number{db::stages::read_stage_progress(*txn, db::stages::kHashStateKey)};
    if (last_processed_block_number != 0) {
        log::Info() << "Starting Account Hashing";
        hashstate_promote(*txn, HashstateOperation::HashAccount);
        log::Info() << "Starting Storage Hashing";
        hashstate_promote(*txn, HashstateOperation::HashStorage);
        log::Info() << "Hashing Code Keys";
        hashstate_promote(*txn, HashstateOperation::Code);
    } else {
        hashstate_promote_clean_state(*txn, etl_path.string());
        hashstate_promote_clean_code(*txn, etl_path.string());
    }
    // Update progress height with last processed block
    db::stages::write_stage_progress(*txn, db::stages::kHashStateKey,
                                     db::stages::read_stage_progress(*txn, db::stages::kExecutionKey));
    txn.commit();

    log::Info() << "All Done!";
    return StageResult::kSuccess;
}

/*
 *  If we have done hashstate before(not first sync),
 *  We need to use changeset because we can use the progress system.
 *  Note: Standard Promotion is way slower than Clean Promotion
 */
static void hashstate_unwind(mdbx::txn& txn, BlockNum unwind_to, HashstateOperation operation) {
    auto [changeset_config, target_config] = get_tables_for_promote(operation);

    auto changeset_table{db::open_cursor(txn, changeset_config)};
    auto target_table{db::open_cursor(txn, target_config)};
    auto code_table{db::open_cursor(txn, db::table::kContractCode)};
    auto contract_code_table{db::open_cursor(txn, db::table::kPlainContractCode)};

    Bytes start_key{db::block_key(unwind_to + 1)};
    auto changeset_data{changeset_table.lower_bound(db::to_slice(start_key), /*throw_notfound=*/false)};
    if (!changeset_data) {
        return;
    }

    db::WalkFunc unwind_func;
    switch (operation) {
        case silkworm::stagedsync::HashstateOperation::HashAccount:
            unwind_func = [&target_table, &code_table](::mdbx::cursor, ::mdbx::cursor::move_result data) -> bool {
                auto [db_key, db_value]{
                    db::change_set_to_plain_state_format(db::from_slice(data.key), db::from_slice(data.value))};

                auto hash{keccak256(db_key)};
                auto new_key{db::to_slice(hash.bytes)};
                if (db_value.empty()) {
                    target_table.erase(new_key);
                    return true;
                }
                auto [acc, err]{Account::from_encoded_storage(db_value)};
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
        case silkworm::stagedsync::HashstateOperation::HashStorage:
            unwind_func = [&target_table](::mdbx::cursor, ::mdbx::cursor::move_result data) -> bool {
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
        case silkworm::stagedsync::HashstateOperation::Code:
            unwind_func = [&target_table, &contract_code_table](::mdbx::cursor,
                                                                ::mdbx::cursor::move_result data) -> bool {
                auto [db_key, db_value]{
                    db::change_set_to_plain_state_format(db::from_slice(data.key), db::from_slice(data.value))};
                if (db_value.empty()) {
                    return true;
                }
                auto [incarnation, err]{Account::incarnation_from_encoded_storage(db_value)};
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
            std::string error{magic_enum::enum_name<HashstateOperation>(operation)};
            error.append(": unknown operation");
            throw std::runtime_error(error);
    }

    (void)db::cursor_for_each(changeset_table, unwind_func);
}

StageResult unwind_hashstate(db::RWTxn& txn, const fs::path&, uint64_t unwind_to) {
    try {
        auto stage_height{db::stages::read_stage_progress(*txn, db::stages::kHashStateKey)};
        if (unwind_to >= stage_height) {
            log::Error() << "Stage progress is " << stage_height << " which is <= than requested unwind_to";
            return StageResult::kAborted;
        }

        log::Info() << "Unwinding HashState from " << stage_height << " to " << unwind_to << " ...";

        log::Info() << "[1/3] Hashed accounts ... ";
        hashstate_unwind(*txn, unwind_to, HashstateOperation::HashAccount);

        log::Info() << "[2/3] Hashed storage ... ";
        hashstate_unwind(*txn, unwind_to, HashstateOperation::HashStorage);

        log::Info() << "[3/3] Code ... ";
        hashstate_unwind(*txn, unwind_to, HashstateOperation::Code);

        // Update progress height with last processed block
        db::stages::write_stage_progress(*txn, db::stages::kHashStateKey, unwind_to);

        log::Info() << "Committing ... ";
        txn.commit();

        log::Info() << "All Done!";
        return StageResult::kSuccess;

    } catch (const std::exception& ex) {
        log::Error() << "Unexpected error : " << ex.what();
        return StageResult::kAborted;
    }
}

}  // namespace silkworm::stagedsync
