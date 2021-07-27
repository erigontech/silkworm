/*
   Copyright 2020-2021 The Silkworm Authors

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
#include <string>

#include <boost/endian/conversion.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/execution/execution.hpp>

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

namespace {
    // block_num is input-output
    StageResult execute_batch_of_blocks(mdbx::txn& txn, const ChainConfig& config, const uint64_t max_block,
                                        const db::StorageMode& storage_mode, const size_t batch_size,
                                        uint64_t& block_num) noexcept {
        db::Buffer buffer{txn};
        AnalysisCache analysis_cache;
        ExecutionStatePool state_pool;

        try {
            while (true) {
                std::optional<BlockWithHash> bh{db::read_block(txn, block_num, /*read_senders=*/true)};
                if (!bh) {
                    return StageResult::kBadChainSequence;
                }

                auto [receipts, err]{execute_block(bh->block, buffer, config, &analysis_cache, &state_pool)};
                if (err != ValidationResult::kOk) {
                    SILKWORM_LOG(LogLevel::Error) << "Validation error " << magic_enum::enum_name<ValidationResult>(err)
                                                  << " at block " << block_num << std::endl;
                    return StageResult::kInvalidBlock;
                }

                if (storage_mode.Receipts) {
                    buffer.insert_receipts(block_num, receipts);
                }

                if (block_num % 1000 == 0) {
                    SILKWORM_LOG(LogLevel::Debug) << "Blocks <= " << block_num << " executed" << std::endl;
                }

                if (buffer.current_batch_size() >= batch_size || block_num >= max_block) {
                    buffer.write_to_db();
                    return StageResult::kSuccess;
                }

                ++block_num;
            }
        } catch (const mdbx::exception& ex) {
            SILKWORM_LOG(LogLevel::Error) << "DB error " << ex.what() << " at block " << block_num << std::endl;
            return StageResult::kDbError;
        } catch (const db::MissingSenders&) {
            SILKWORM_LOG(LogLevel::Error) << "Missing or incorrect senders at block " << block_num << std::endl;
            return StageResult::kMissingSenders;
        } catch (const rlp::DecodingError& ex) {
            SILKWORM_LOG(LogLevel::Error) << ex.what() << " at block " << block_num << std::endl;
            return StageResult::kDecodingError;
        } catch (const std::exception& ex) {
            SILKWORM_LOG(LogLevel::Error) << "Unexpected error " << ex.what() << " at block " << block_num << std::endl;
            return StageResult::kUnexpectedError;
        } catch (...) {
            SILKWORM_LOG(LogLevel::Error) << "Unkown error at block " << block_num << std::endl;
            return StageResult::kUnknownError;
        }
    }
}  // namespace

StageResult stage_execution(db::EnvConfig db_config, size_t batch_size) {
    StageResult res{StageResult::kSuccess};

    try {
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};

        const auto chain_config{db::read_chain_config(txn)};
        if (!chain_config.has_value()) {
            return StageResult::kUnknownChainId;
        }
        const auto storage_mode{db::read_storage_mode(txn)};

        uint64_t max_block{db::stages::get_stage_progress(txn, db::stages::kBlockBodiesKey)};
        uint64_t block_num{db::stages::get_stage_progress(txn, db::stages::kExecutionKey) + 1};
        if (block_num > max_block) {
            SILKWORM_LOG(LogLevel::Error) << "Stage progress is " << (block_num - 1)
                                          << " which is <= than requested block_to " << max_block << std::endl;
            return StageResult::kInvalidRange;
        }

        // Execution needs senders hence we need to check whether or not sender's stage is
        // at least at max_block as set above
        uint64_t max_block_senders{db::stages::get_stage_progress(txn, db::stages::kSendersKey)};
        if (max_block > max_block_senders) {
            SILKWORM_LOG(LogLevel::Error) << "Sender's stage progress is " << (max_block_senders)
                                          << " which is <= than requested block_to " << max_block << std::endl;
            return StageResult::kMissingSenders;
        }

        StopWatch sw{};
        (void)sw.start();

        for (; block_num <= max_block; ++block_num) {
            res = execute_batch_of_blocks(txn, chain_config.value(), max_block, storage_mode, batch_size, block_num);
            if (res == StageResult::kSuccess) {
                db::stages::set_stage_progress(txn, db::stages::kExecutionKey, block_num);
                txn.commit();
                (void)sw.lap();
                SILKWORM_LOG(LogLevel::Info)
                    << (block_num == max_block ? "All blocks" : "Blocks") << " <= " << block_num << " committed"
                    << " in " << sw.format(sw.laps().back().second) << std::endl;
                txn = env.start_write();
            } else {
                break;
            }
        };

    } catch (const mdbx::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << "DB Error " << ex.what() << " in stage_execution" << std::endl;
        return StageResult::kDbError;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << "Unexpected error " << ex.what() << " in stage execution " << std::endl;
        return StageResult::kUnexpectedError;
    }

    return res;
}

// Revert State for given address/storage location
void revert_state(Bytes key, Bytes value, mdbx::cursor& plain_state_table, mdbx::cursor& plain_code_table) {
    if (key.size() == kAddressLength) {
        if (value.size() > 0) {
            auto [account, err]{decode_account_from_storage(value)};
            rlp::err_handler(err);
            if (account.incarnation > 0 && account.code_hash == kEmptyHash) {
                Bytes code_hash_key(kAddressLength + db::kIncarnationLength, '\0');
                std::memcpy(&code_hash_key[0], &key[0], kAddressLength);
                boost::endian::store_big_u64(&code_hash_key[kAddressLength], account.incarnation);
                auto new_code_hash{plain_code_table.find(db::to_slice(code_hash_key))};
                std::memcpy(&account.code_hash.bytes[0], new_code_hash.value.iov_base, kHashLength);
            }
            // cleaning up contract codes
            auto state_account_encoded{plain_state_table.find(db::to_slice(key), /*throw_notfound=*/false)};
            if (state_account_encoded) {
                auto [state_incarnation, err]{extract_incarnation(db::from_slice(state_account_encoded.value))};
                rlp::err_handler(err);
                // cleanup each code incarnation
                for (uint64_t i = state_incarnation; i > account.incarnation && i > 0; --i) {
                    Bytes key_hash(kAddressLength + 8, '\0');
                    std::memcpy(&key_hash[0], key.data(), kAddressLength);
                    boost::endian::store_big_u64(&key_hash[kAddressLength], i);
                    if (plain_code_table.seek(db::to_slice(key_hash))) {
                        plain_code_table.erase();
                    }
                }
            }
            auto new_encoded_account{account.encode_for_storage(false)};
            if (plain_state_table.seek(db::to_slice(key))) {
                plain_state_table.erase(/*whole_multivalue*/ true);
            }
            plain_state_table.upsert(db::to_slice(key), db::to_slice(new_encoded_account));
        } else {
            if (plain_code_table.seek(db::to_slice(key))) {
                plain_code_table.erase();
            }
        }
        return;
    }
    auto location{key.substr(kAddressLength + db::kIncarnationLength)};
    auto key1{key.substr(0, kAddressLength + db::kIncarnationLength)};
    if (db::find_value_suffix(plain_state_table, key1, location) != std::nullopt) {
        plain_state_table.erase();
    }
    if (value.size() > 0) {
        auto data{location.append(value)};
        plain_state_table.upsert(db::to_slice(key1), db::to_slice(data));
    }
    return;
}

// For given changeset cursor/bucket it reverts the changes on states buckets
void unwind_state_from_changeset(mdbx::cursor& source, mdbx::cursor& plain_state_table, mdbx::cursor& plain_code_table,
                                 uint64_t unwind_to) {
    uint64_t block_number{0};
    auto src_data{source.to_last(/*throw_notfound*/ false)};
    while (src_data) {
        Bytes key(db::from_slice(src_data.key));
        Bytes value(db::from_slice(src_data.value));
        block_number = boost::endian::load_big_u64(&key[0]);
        if (block_number == unwind_to) {
            break;
        }
        auto [new_key, new_value]{convert_to_db_format(key, value)};
        revert_state(new_key, new_value, plain_state_table, plain_code_table);
        src_data = source.to_previous(/*throw_notfound*/ false);
    }
}

void unwind_table_from(mdbx::cursor& table, Bytes& starting_key) {
    if (table.seek(db::to_slice(starting_key))) {
        table.erase();
        while (table.to_next(/*throw_notfound*/ false)) {
            table.erase();
        }
    }
}

StageResult unwind_execution(db::EnvConfig db_config, uint64_t unwind_to) {
    auto env{db::open_env(db_config)};
    auto txn{env.start_write()};
    uint64_t block_number{db::stages::get_stage_progress(txn, db::stages::kExecutionKey)};

    auto plain_state_table{db::open_cursor(txn, db::table::kPlainState)};
    auto plain_code_table{db::open_cursor(txn, db::table::kPlainContractCode)};
    auto account_changeset_table{db::open_cursor(txn, db::table::kPlainAccountChangeSet)};
    auto storage_changeset_table{db::open_cursor(txn, db::table::kPlainStorageChangeSet)};
    auto receipts_table{db::open_cursor(txn, db::table::kBlockReceipts)};
    auto log_table{db::open_cursor(txn, db::table::kLogs)};
    auto traces_table{db::open_cursor(txn, db::table::kCallTraceSet)};

    if (unwind_to == 0) {
        txn.clear_map(plain_state_table.map());
        txn.clear_map(plain_code_table.map());
        txn.clear_map(account_changeset_table.map());
        txn.clear_map(storage_changeset_table.map());
        txn.clear_map(receipts_table.map());
        txn.clear_map(log_table.map());
        txn.clear_map(traces_table.map());
        db::stages::set_stage_progress(txn, db::stages::kExecutionKey, 0);
        txn.commit();
        return StageResult::kSuccess;
    }

    if (unwind_to >= block_number) {
        return StageResult::kSuccess;
    }

    SILKWORM_LOG(LogLevel::Info) << "Unwind Execution from " << block_number << " to " << unwind_to << std::endl;

    unwind_state_from_changeset(account_changeset_table, plain_state_table, plain_code_table, unwind_to);
    unwind_state_from_changeset(storage_changeset_table, plain_state_table, plain_code_table, unwind_to);
    // We set the cursor data
    Bytes unwind_to_bytes(8, '\0');
    boost::endian::store_big_u64(&unwind_to_bytes[0], unwind_to + 1);

    // Truncate Tables
    unwind_table_from(account_changeset_table, unwind_to_bytes);
    unwind_table_from(storage_changeset_table, unwind_to_bytes);
    unwind_table_from(receipts_table, unwind_to_bytes);
    unwind_table_from(log_table, unwind_to_bytes);
    unwind_table_from(traces_table, unwind_to_bytes);

    db::stages::set_stage_progress(txn, db::stages::kExecutionKey, unwind_to);
    txn.commit();

    return StageResult::kSuccess;
}
}  // namespace silkworm::stagedsync
