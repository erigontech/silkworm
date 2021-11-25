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

#include <silkworm/chain/config.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/consensus/engine.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/execution/processor.hpp>

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

// block_num is input-output
static StageResult execute_batch_of_blocks(mdbx::txn& txn, const ChainConfig& config, const BlockNum max_block,
                                           const size_t batch_size, BlockNum& block_num, BlockNum prune_from) noexcept {
    try {
        db::Buffer buffer{txn, prune_from};
        AnalysisCache analysis_cache;
        ExecutionStatePool state_pool;
        std::vector<Receipt> receipts;
        auto consensus_engine{consensus::engine_factory(config)};
        if (!consensus_engine) {
            return StageResult::kUnknownConsensusEngine;
        }
        while (true) {
            std::optional<BlockWithHash> bh{db::read_block(txn, block_num, /*read_senders=*/true)};
            if (!bh.has_value()) {
                return StageResult::kBadChainSequence;
            }

            ExecutionProcessor processor{bh->block, *consensus_engine, buffer, config};
            processor.evm().advanced_analysis_cache = &analysis_cache;
            processor.evm().state_pool = &state_pool;

            if (const auto res{processor.execute_and_write_block(receipts)}; res != ValidationResult::kOk) {
                log::Error() << "Validation error " << magic_enum::enum_name<ValidationResult>(res)
                                    << " at block " << block_num;
                return StageResult::kInvalidBlock;
            }

            // TODO(Andrea) implement pruning
            buffer.insert_receipts(block_num, receipts);

            if (block_num % 1000 == 0) {
                log::Debug() << "Blocks <= " << block_num << " executed";
            }

            if (buffer.current_batch_size() >= batch_size || block_num >= max_block) {
                buffer.write_to_db();
                return StageResult::kSuccess;
            }

            ++block_num;
        }
    } catch (const mdbx::exception& ex) {
        log::Error() << "DB error " << ex.what() << " at block " << block_num;
        return StageResult::kDbError;
    } catch (const db::MissingSenders&) {
        log::Error() << "Missing or incorrect senders at block " << block_num;
        return StageResult::kMissingSenders;
    } catch (const rlp::DecodingError& ex) {
        log::Error() << ex.what() << " at block " << block_num;
        return StageResult::kDecodingError;
    } catch (const std::exception& ex) {
        log::Error() << "Unexpected error " << ex.what() << " at block " << block_num;
        return StageResult::kUnexpectedError;
    } catch (...) {
        log::Error() << "Unknown error at block " << block_num;
        return StageResult::kUnknownError;
    }
}

StageResult stage_execution(db::RWTxn& txn, const std::filesystem::path&, size_t batch_size,
                            uint64_t prune_from) {
    StageResult res{StageResult::kSuccess};

    try {
        const auto chain_config{db::read_chain_config(*txn)};
        if (!chain_config.has_value()) {
            return StageResult::kUnknownChainId;
        }

        const BlockNum max_block{db::stages::read_stage_progress(*txn, db::stages::kBlockBodiesKey)};
        BlockNum block_num{db::stages::read_stage_progress(*txn, db::stages::kExecutionKey) + 1};
        if (block_num > max_block) {
            log::Error() << "Stage progress is " << (block_num - 1) << " which is <= than requested block_to "
                                << max_block;
            return StageResult::kInvalidRange;
        }

        // Execution needs senders hence we need to check whether sender's stage is
        // at least at max_block as set above
        const BlockNum max_block_senders{db::stages::read_stage_progress(*txn, db::stages::kSendersKey)};
        if (max_block > max_block_senders) {
            log::Error() << "Sender's stage progress is " << (max_block_senders)
                                << " which is <= than requested block_to " << max_block;
            return StageResult::kMissingSenders;
        }

        StopWatch sw{};
        (void)sw.start();

        for (; block_num <= max_block; ++block_num) {
            res = execute_batch_of_blocks(*txn, chain_config.value(), max_block, batch_size, block_num, prune_from);
            if (res != StageResult::kSuccess) {
                return res;
            }

            db::stages::write_stage_progress(*txn, db::stages::kExecutionKey, block_num);

            txn.commit();

            (void)sw.lap();
            log::Info() << (block_num == max_block ? "All blocks" : "Blocks") << " <= " << block_num
                               << " committed"
                               << " in " << StopWatch::format(sw.laps().back().second);
        }
    } catch (const mdbx::exception& ex) {
        log::Error() << "DB Error " << ex.what() << " in stage_execution";
        return StageResult::kDbError;
    } catch (const std::exception& ex) {
        log::Error() << "Unexpected error " << ex.what() << " in stage execution";
        return StageResult::kUnexpectedError;
    }

    return res;
}

// Revert State for given address/storage location
static void revert_state(ByteView key, ByteView value, mdbx::cursor& plain_state_table,
                         mdbx::cursor& plain_code_table) {
    if (key.size() == kAddressLength) {
        if (!value.empty()) {
            auto [account, err1]{decode_account_from_storage(value)};
            rlp::success_or_throw(err1);
            if (account.incarnation > 0 && account.code_hash == kEmptyHash) {
                Bytes code_hash_key(kAddressLength + db::kIncarnationLength, '\0');
                std::memcpy(&code_hash_key[0], &key[0], kAddressLength);
                endian::store_big_u64(&code_hash_key[kAddressLength], account.incarnation);
                auto new_code_hash{plain_code_table.find(db::to_slice(code_hash_key))};
                std::memcpy(&account.code_hash.bytes[0], new_code_hash.value.iov_base, kHashLength);
            }
            // cleaning up contract codes
            auto state_account_encoded{plain_state_table.find(db::to_slice(key), /*throw_notfound=*/false)};
            if (state_account_encoded) {
                auto [state_incarnation, err2]{extract_incarnation(db::from_slice(state_account_encoded.value))};
                rlp::success_or_throw(err2);
                // cleanup each code incarnation
                for (uint64_t i = state_incarnation; i > account.incarnation; --i) {
                    Bytes key_hash(kAddressLength + 8, '\0');
                    std::memcpy(&key_hash[0], key.data(), kAddressLength);
                    endian::store_big_u64(&key_hash[kAddressLength], i);
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
    if (!value.empty()) {
        Bytes data{location};
        data.append(value);
        plain_state_table.upsert(db::to_slice(key1), db::to_slice(data));
    }
}

// For given changeset cursor/bucket it reverts the changes on states buckets
static void unwind_state_from_changeset(mdbx::cursor& source, mdbx::cursor& plain_state_table,
                                        mdbx::cursor& plain_code_table, BlockNum unwind_to) {
    auto src_data{source.to_last(/*throw_notfound*/ false)};
    while (src_data) {
        Bytes key(db::from_slice(src_data.key));
        Bytes value(db::from_slice(src_data.value));
        const BlockNum block_number = endian::load_big_u64(&key[0]);
        if (block_number == unwind_to) {
            break;
        }
        auto [new_key, new_value]{db::change_set_to_plain_state_format(key, value)};
        revert_state(new_key, new_value, plain_state_table, plain_code_table);
        src_data = source.to_previous(/*throw_notfound*/ false);
    }
}

StageResult unwind_execution(db::RWTxn& txn, const std::filesystem::path&, uint64_t unwind_to) {
    BlockNum execution_progress{db::stages::read_stage_progress(*txn, db::stages::kExecutionKey)};
    if (unwind_to >= execution_progress) {
        return StageResult::kSuccess;
    }

    log::Info() << "Unwind Execution from " << execution_progress << " to " << unwind_to;

    static const db::MapConfig unwind_tables[7] = {
        db::table::kPlainState,         //
        db::table::kPlainContractCode,  //
        db::table::kAccountChangeSet,   //
        db::table::kStorageChangeSet,   //
        db::table::kBlockReceipts,      //
        db::table::kLogs,               //
        db::table::kCallTraceSet        //
    };

    try {
        if (unwind_to == 0) {
            for (const auto& unwind_table : unwind_tables) {
                auto unwind_map_handle{db::open_map(*txn, unwind_table)};
                txn->clear_map(unwind_map_handle);
            }
        } else {
            {
                auto plain_state_table{db::open_cursor(*txn, db::table::kPlainState)};
                auto plain_code_table{db::open_cursor(*txn, db::table::kPlainContractCode)};
                auto account_changeset_table{db::open_cursor(*txn, db::table::kAccountChangeSet)};
                auto storage_changeset_table{db::open_cursor(*txn, db::table::kStorageChangeSet)};
                unwind_state_from_changeset(account_changeset_table, plain_state_table, plain_code_table, unwind_to);
                unwind_state_from_changeset(storage_changeset_table, plain_state_table, plain_code_table, unwind_to);
            }

            // Delete records which has keys greater than unwind point
            // Note erasing forward the start key is included that's why we increase unwind_to by 1
            Bytes start_key(8, '\0');
            endian::store_big_u64(&start_key[0], unwind_to + 1);
            for (int i = 2; i < 7; ++i) {
                auto unwind_cursor{db::open_cursor(*txn, unwind_tables[i])};
                auto erased{db::cursor_erase(unwind_cursor, start_key, db::CursorMoveDirection::Forward)};
                log::Info() << "Erased " << erased << " records from " << unwind_tables[i].name;
                unwind_cursor.close();
            }
        }
        txn.commit();
        return StageResult::kSuccess;
    } catch (const mdbx::exception& ex) {
        log::Error() << "Unexpected db error in " << std::string(__FUNCTION__) << " : " << ex.what();
        return StageResult::kDbError;
    } catch (...) {
        log::Error() << "Unexpected unknown error in " << std::string(__FUNCTION__);
        return StageResult::kUnexpectedError;
    }
}

StageResult prune_execution(db::RWTxn& txn, const std::filesystem::path&, uint64_t prune_from) {
    static const db::MapConfig prune_tables[] = {
        db::table::kAccountChangeSet,  //
        db::table::kStorageChangeSet,  //
        db::table::kBlockReceipts,     //
        db::table::kCallTraceSet,      //
        db::table::kLogs               //
    };

    try {
        const auto prune_point{db::block_key(prune_from)};
        for (const auto& prune_table : prune_tables) {
            auto prune_cursor{db::open_cursor(*txn, prune_table)};
            auto erased{db::cursor_erase(prune_cursor, prune_point, db::CursorMoveDirection::Reverse)};
            log::Info() << "Erased " << erased << " records from " << prune_table.name;
            prune_cursor.close();
        }
        txn.commit();  // TODO(Giulio) Should we commit here or at return of stage ?
        return StageResult::kSuccess;
    } catch (const mdbx::exception& ex) {
        log::Error() << "Unexpected db error in " << std::string(__FUNCTION__) << " : " << ex.what();
        return StageResult::kDbError;
    } catch (...) {
        log::Error() << "Unexpected unknown error in " << std::string(__FUNCTION__);
        return StageResult::kUnexpectedError;
    }
}

}  // namespace silkworm::stagedsync
