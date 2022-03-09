/*
   Copyright 2020-2022 The Silkworm Authors

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

#include "stage_execution.hpp"

#include <string>

#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/execution/processor.hpp>

namespace silkworm::stagedsync {

StageResult Execution::forward(db::RWTxn& txn) {
    if (is_stopping()) {
        return StageResult::kAborted;
    } else if (!node_settings_->chain_config.has_value()) {
        return StageResult::kUnknownChainId;
    } else if (!consensus_engine_) {
        return StageResult::kUnknownConsensusEngine;
    }

    StopWatch commit_stopwatch;
    // Check stage boundaries from previous execution and previous stage execution
    auto previous_progress{get_progress(txn)};
    auto headers_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kHeadersKey)};
    auto bodies_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kBlockBodiesKey)};
    auto senders_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kSendersKey)};

    // This is next stage probably needing full history
    auto hashstate_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kHashStateKey)};

    if (previous_progress == bodies_stage_progress) {
        // Nothing to process
        return StageResult::kSuccess;
    } else if (previous_progress > bodies_stage_progress) {
        // Something bad had happened. Not possible execution stage is ahead of bodies
        // Maybe we need to unwind ?
        log::Error() << "Bad progress sequence. Execution stage progress " << previous_progress
                     << " while Bodies stage " << bodies_stage_progress;
        return StageResult::kInvalidProgress;
    } else if (previous_progress > senders_stage_progress) {
        // Same as above but for senders
        log::Error() << "Bad progress sequence. Execution stage progress " << previous_progress
                     << " while Senders stage " << senders_stage_progress;
        return StageResult::kInvalidProgress;
    }

    std::unique_lock progress_lock(progress_mtx_);
    processed_blocks_ = 0;
    processed_transactions_ = 0;
    processed_gas_ = 0;
    lap_time_ = std::chrono::steady_clock::now();
    progress_lock.unlock();

    block_num_ = previous_progress + 1;
    BlockNum max_block_num{bodies_stage_progress};
    if (bodies_stage_progress - previous_progress > 16) {
        log::Info("Begin Execution", {"from", std::to_string(block_num_), "to", std::to_string(bodies_stage_progress)});
    }

    // Determine pruning thresholds on behalf of current db pruning mode and verify next stage does not need
    // prune-able data
    BlockNum prune_history{node_settings_->prune_mode->history().value_from_head(headers_stage_progress)};
    BlockNum prune_receipts{node_settings_->prune_mode->receipts().value_from_head(headers_stage_progress)};
    if (hashstate_stage_progress) {
        prune_history = std::min(prune_history, hashstate_stage_progress - 1);
        prune_receipts = std::min(prune_receipts, hashstate_stage_progress - 1);
    }

    AnalysisCache analysis_cache;
    ObjectPool<EvmoneExecutionState> state_pool;

    while (!is_stopping() && block_num_ <= max_block_num) {
        const auto res{execute_batch(txn, max_block_num, analysis_cache, state_pool, prune_history, prune_receipts)};
        if (res != StageResult::kSuccess) {
            return res;
        }

        // Persist forward and prune progresses
        db::stages::write_stage_progress(*txn, db::stages::kExecutionKey, block_num_);
        if (node_settings_->prune_mode->history().enabled() || node_settings_->prune_mode->receipts().enabled()) {
            db::stages::write_stage_prune_progress(*txn, db::stages::kExecutionKey, block_num_);
        }

        (void)commit_stopwatch.start(/*with_reset=*/true);
        txn.commit();
        auto [_, duration]{commit_stopwatch.stop()};
        log::Info("Commit time", {"batch", StopWatch::format(duration)});
        block_num_++;
    }
    return is_stopping() ? StageResult::kAborted : StageResult::kSuccess;
}

std::queue<Block> Execution::prefetch_blocks(db::RWTxn& txn, BlockNum from, BlockNum to, size_t max_blocks) {
    std::unique_ptr<StopWatch> sw;
    if (log::test_verbosity(log::Level::kTrace)) {
        sw = std::make_unique<StopWatch>(/*auto_start=*/true);
    }

    std::queue<Block> ret{};
    auto hashes_table{db::open_cursor(*txn, db::table::kCanonicalHashes)};
    auto key{db::block_key(from)};
    auto data{hashes_table.find(db::to_slice(key), true)};
    while (data.done) {
        BlockNum reached_block_num{endian::load_big_u64(static_cast<const uint8_t*>(data.key.data()))};
        if (reached_block_num != from) {
            throw std::runtime_error("Bad canonical header sequence: expected " + std::to_string(from) + " got " +
                                     std::to_string(reached_block_num));
        }

        Bytes block_key(8 + kHashLength, '\0');
        std::memcpy(&block_key[0], data.key.data(), 8);
        std::memcpy(&block_key[8], data.value.data(), kHashLength);

        Block block{};
        auto raw_header{db::read_header_raw(*txn, block_key)};
        if (raw_header.empty()) {
            throw std::runtime_error("Unable to load block header for block " + std::to_string(from));
        }
        ByteView encoded_header{raw_header.data(), raw_header.length()};
        rlp::success_or_throw(rlp::decode(encoded_header, block.header));

        if (!db::read_body(*txn, block_key, /*read_senders=*/true, block)) {
            throw std::runtime_error("Unable to load block body for block " + std::to_string(from));
        }
        ret.push(block);

        if (from == to || ret.size() >= max_blocks) {
            break;
        }

        ++from;
        data = hashes_table.to_next(false);
    }
    if (sw) {
        auto [_, duration]{sw->lap()};
        log::Trace("Fetched blocks", {"size", std::to_string(ret.size()), "in", StopWatch::format(duration)});
    }
    return ret;
}

StageResult Execution::execute_batch(db::RWTxn& txn, BlockNum max_block_num, AnalysisCache& analysis_cache,
                                     ObjectPool<EvmoneExecutionState>& state_pool, BlockNum prune_history_threshold,
                                     BlockNum prune_receipts_threshold) {
    try {
        db::Buffer buffer(*txn, prune_history_threshold);
        std::vector<Receipt> receipts;

        // Transform batch_size limit into Ggas
        size_t gas_max_history_size{node_settings_->batch_size * 1_Kibi / 2};  // 512MB -> 256Ggas roughly
        size_t gas_max_batch_size{gas_max_history_size * 20};                  // 256Ggas -> 5Tgas roughly
        size_t gas_history_size{0};
        size_t gas_batch_size{0};

        {
            std::unique_lock progress_lock(progress_mtx_);
            lap_time_ = std::chrono::steady_clock::now();
        }

        size_t kDefaultPrefetchWidth{10240};
        std::queue<Block> prefetched_blocks{prefetch_blocks(txn, block_num_, max_block_num, kDefaultPrefetchWidth)};

        while (true) {
            if (prefetched_blocks.empty()) {
                if (is_stopping()) {
                    return StageResult::kAborted;
                }
                prefetched_blocks = prefetch_blocks(txn, block_num_, max_block_num, kDefaultPrefetchWidth);
            }

            auto block = prefetched_blocks.front();
            if (block.header.number != block_num_) {
                throw std::runtime_error("Bad block sequence");
            }

            if ((block_num_ % 64 == 0) && is_stopping()) {
                return StageResult::kAborted;
            }

            ExecutionProcessor processor(block, *consensus_engine_, buffer, node_settings_->chain_config.value());
            processor.evm().advanced_analysis_cache = &analysis_cache;
            processor.evm().state_pool = &state_pool;

            // TODO(Andrea) Add Tracer

            if (const auto res{processor.execute_and_write_block(receipts)}; res != ValidationResult::kOk) {
                const auto block_hash_hex{to_hex(block.header.hash().bytes, true)};
                log::Error("Block Validation Error",
                           {"block", std::to_string(block_num_), "hash", block_hash_hex, "err",
                            std::string(magic_enum::enum_name<ValidationResult>(res))});
                // TODO(Andrea) Set the bad block hash in stage loop context so other stages are aware
                return StageResult::kInvalidBlock;
            }

            if (block_num_ >= prune_receipts_threshold) {
                buffer.insert_receipts(block_num_, receipts);
            }

            // Stats
            std::unique_lock progress_lock(progress_mtx_);
            ++processed_blocks_;
            processed_transactions_ += block.transactions.size();
            processed_gas_ += block.header.gas_used;
            gas_batch_size += block.header.gas_used;
            gas_history_size += block.header.gas_used;
            progress_lock.unlock();

            // Flush whole buffer if time to
            if (gas_batch_size >= gas_max_batch_size || block_num_ >= max_block_num) {
                log::Trace("Buffer State", {"size", human_size(buffer.current_batch_state_size())});
                buffer.write_to_db();
                break;
            } else if (gas_history_size >= gas_max_history_size) {
                // or flush history only if needed
                log::Trace("Buffer History", {"size", human_size(buffer.current_batch_history_size())});
                buffer.write_history_to_db();
                gas_history_size = 0;
            }

            ++block_num_;
            prefetched_blocks.pop();
        }

        return is_stopping() ? StageResult::kAborted : StageResult::kSuccess;

    } catch (const mdbx::exception& ex) {
        log::Error("DB Error", {"block", std::to_string(block_num_)}) << " " << ex.what();
        return StageResult::kDbError;
    } catch (const rlp::DecodingError& ex) {
        log::Error("RLP decoding error", {"block", std::to_string(block_num_)}) << " " << ex.what();
        return StageResult::kDecodingError;
    } catch (const std::exception& ex) {
        log::Error("Unexpected error", {"block", std::to_string(block_num_)}) << " " << ex.what();
        return StageResult::kUnexpectedError;
    } catch (...) {
        log::Error("Unexpected undefined error", {"block", std::to_string(block_num_)});
        return StageResult::kUnknownError;
    }
}

StageResult Execution::unwind(db::RWTxn& txn, BlockNum to) {
    BlockNum execution_progress{db::stages::read_stage_progress(*txn, db::stages::kExecutionKey)};
    if (to >= execution_progress) {
        return StageResult::kSuccess;
    }

    log::Info() << "Unwind Execution from " << execution_progress << " to " << to;

    static const db::MapConfig unwind_tables[5] = {
        db::table::kAccountChangeSet,  //
        db::table::kStorageChangeSet,  //
        db::table::kBlockReceipts,     //
        db::table::kLogs,              //
        db::table::kCallTraceSet       //
    };

    try {
        {
            // Revert states
            auto plain_state_table{db::open_cursor(*txn, db::table::kPlainState)};
            auto plain_code_table{db::open_cursor(*txn, db::table::kPlainCodeHash)};
            auto account_changeset_table{db::open_cursor(*txn, db::table::kAccountChangeSet)};
            auto storage_changeset_table{db::open_cursor(*txn, db::table::kStorageChangeSet)};
            unwind_state_from_changeset(account_changeset_table, plain_state_table, plain_code_table, to);
            unwind_state_from_changeset(storage_changeset_table, plain_state_table, plain_code_table, to);
        }

        // Delete records which has keys greater than unwind point
        // Note erasing forward the start key is included that's why we increase unwind_to by 1
        Bytes start_key(8, '\0');
        endian::store_big_u64(&start_key[0], to + 1);
        for (const auto& map_config : unwind_tables) {
            auto unwind_cursor{db::open_cursor(*txn, map_config)};
            auto erased{db::cursor_erase(unwind_cursor, start_key, db::CursorMoveDirection::Forward)};
            log::Info() << "Erased " << erased << " records from " << map_config.name;
        }
        db::stages::write_stage_progress(*txn, db::stages::kExecutionKey, to);
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

StageResult Execution::prune(db::RWTxn& txn) {
    try {
        BlockNum execution_progress{db::stages::read_stage_progress(*txn, stage_name_)};
        BlockNum prune_progress{db::stages::read_stage_prune_progress(*txn, stage_name_)};
        if (prune_progress >= execution_progress) {
            return StageResult::kSuccess;
        }

        if (node_settings_->prune_mode->history().enabled()) {
            auto prune_from{node_settings_->prune_mode->history().value_from_head(execution_progress)};
            auto key{db::block_key(prune_from)};
            size_t erased{0};
            auto origin{db::open_cursor(*txn, db::table::kAccountChangeSet)};
            auto data{origin.lower_bound(db::to_slice(key), /*throw_notfound=*/false)};
            while (data) {
                erased += origin.count_multivalue();
                origin.erase(/*whole_multivalue=*/true);
                data = origin.to_previous(/*throw_notfound=*/false);
            }
            log::Info() << "Erased " << erased << " records from " << db::table::kAccountChangeSet.name;

            origin.close();
            origin = db::open_cursor(*txn, db::table::kStorageChangeSet);
            data = origin.lower_bound(db::to_slice(key), /*throw_notfound=*/false);
            while (data) {
                auto data_value_view{db::from_slice(data.value)};
                if (endian::load_big_u64(data_value_view.data()) < prune_from) {
                    erased += origin.count_multivalue();
                    origin.erase(/*whole_multivalue=*/true);
                }
                data = origin.to_previous(/*throw_notfound=*/false);
            }
            log::Info() << "Erased " << erased << " records from " << db::table::kStorageChangeSet.name;
        }

        if (node_settings_->prune_mode->receipts().enabled()) {
            auto prune_from{node_settings_->prune_mode->receipts().value_from_head(execution_progress)};
            auto key{db::block_key(prune_from)};
            auto origin{db::open_cursor(*txn, db::table::kBlockReceipts)};
            size_t erased = db::cursor_erase(origin, key, db::CursorMoveDirection::Reverse);
            log::Info() << "Erased " << erased << " records from " << db::table::kBlockReceipts.name;
            origin.close();
            origin = db::open_cursor(*txn, db::table::kLogs);
            erased = db::cursor_erase(origin, key, db::CursorMoveDirection::Reverse);
            log::Info() << "Erased " << erased << " records from " << db::table::kLogs.name;
        }

        // TODO Re-Enable this when we'll have call traces collection enabled in forward

        //        if (node_settings_->prune_mode->call_traces().enabled()) {
        //            auto prune_from{node_settings_->prune_mode->receipts().value_from_head(execution_progress)};
        //            auto key{db::block_key(prune_from)};
        //            auto origin{db::open_cursor(*txn, db::table::kCallTraceSet)};
        //            size_t erased = db::cursor_erase(origin, key, db::CursorMoveDirection::Reverse);
        //            log::Info() << "Erased " << erased << " records from " << db::table::kCallTraceSet.name;
        //        }

        db::stages::write_stage_prune_progress(*txn, db::stages::kExecutionKey, execution_progress);
        txn.commit();
        return StageResult::kSuccess;
    } catch (const mdbx::exception& ex) {
        log::Error() << "Unexpected db error in " << std::string(__FUNCTION__) << " : " << ex.what();
        return StageResult::kDbError;
    } catch (...) {
        log::Error() << "Unexpected unknown error in " << std::string(__FUNCTION__);
        return StageResult::kUnexpectedError;
    }
};

std::vector<std::string> Execution::get_log_progress() {
    std::unique_lock progress_lock(progress_mtx_);
    auto now{std::chrono::steady_clock::now()};
    auto elapsed{now - lap_time_};
    lap_time_ = now;
    auto elapsed_seconds = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count());
    if (!elapsed_seconds || !processed_blocks_) {
        return {"block", std::to_string(block_num_), "db", "waiting ..."};
    }
    auto speed_blocks = processed_blocks_ / elapsed_seconds;
    auto speed_transactions = processed_transactions_ / elapsed_seconds;
    auto speed_mgas = processed_gas_ / elapsed_seconds / 1'000'000;
    processed_blocks_ = 0;
    processed_transactions_ = 0;
    processed_gas_ = 0;
    progress_lock.unlock();

    return {"block",  std::to_string(block_num_),         "blocks/s", std::to_string(speed_blocks),
            "txns/s", std::to_string(speed_transactions), "Mgas/s",   std::to_string(speed_mgas)};
}

void Execution::revert_state(ByteView key, ByteView value, mdbx::cursor& plain_state_table,
                             mdbx::cursor& plain_code_table) {
    if (key.size() == kAddressLength) {
        if (!value.empty()) {
            auto [account, err1]{Account::from_encoded_storage(value)};
            rlp::success_or_throw(err1);
            if (account.incarnation > 0 && account.code_hash == kEmptyHash) {
                Bytes code_hash_key(kAddressLength + db::kIncarnationLength, '\0');
                std::memcpy(&code_hash_key[0], &key[0], kAddressLength);
                endian::store_big_u64(&code_hash_key[kAddressLength], account.incarnation);
                auto new_code_hash{plain_code_table.find(db::to_slice(code_hash_key))};
                std::memcpy(&account.code_hash.bytes[0], new_code_hash.value.data(), kHashLength);
            }
            // cleaning up contract codes
            auto state_account_encoded{plain_state_table.find(db::to_slice(key), /*throw_notfound=*/false)};
            if (state_account_encoded) {
                auto [state_incarnation,
                      err2]{Account::incarnation_from_encoded_storage(db::from_slice(state_account_encoded.value))};
                rlp::success_or_throw(err2);
                // cleanup each code incarnation
                for (uint64_t i = state_incarnation; i > account.incarnation; --i) {
                    Bytes key_hash(kAddressLength + 8, '\0');
                    std::memcpy(&key_hash[0], key.data(), kAddressLength);
                    endian::store_big_u64(&key_hash[kAddressLength], i);
                    plain_code_table.erase(db::to_slice(key_hash));
                }
            }
            auto new_encoded_account{account.encode_for_storage(false)};
            plain_state_table.erase(db::to_slice(key), /*whole_multivalue=*/true);
            plain_state_table.upsert(db::to_slice(key), db::to_slice(new_encoded_account));
        } else {
            plain_state_table.erase(db::to_slice(key));
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

void Execution::unwind_state_from_changeset(mdbx::cursor& source_changeset, mdbx::cursor& plain_state_table,
                                            mdbx::cursor& plain_code_table, BlockNum unwind_to) {
    auto src_data{source_changeset.to_last(/*throw_notfound*/ false)};
    while (src_data) {
        auto key(db::from_slice(src_data.key));
        auto value(db::from_slice(src_data.value));
        const BlockNum block_number = endian::load_big_u64(&key[0]);
        if (block_number <= unwind_to) {
            break;
        }
        auto [new_key, new_value]{db::changeset_to_plainstate_format(key, value)};
        revert_state(new_key, new_value, plain_state_table, plain_code_table);
        src_data = source_changeset.to_previous(/*throw_notfound*/ false);
    }

    // TODO(Andrea) Explain why we need to leave unwound changeset in place
}

}  // namespace silkworm::stagedsync
