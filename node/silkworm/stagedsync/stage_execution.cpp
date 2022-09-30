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

#include "stage_execution.hpp"

#include <span>

#include <silkworm/common/endian.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/execution/processor.hpp>

namespace silkworm::stagedsync {

Stage::Result Execution::forward(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::Forward;
    try {
        throw_if_stopping();
        if (!node_settings_->chain_config.has_value()) {
            throw StageError(Stage::Result::kUnknownChainId);
        }
        if (!consensus_engine_) {
            throw StageError(Stage::Result::kUnknownConsensusEngine);
        }

        StopWatch commit_stopwatch;
        // Check stage boundaries from previous execution and previous stage execution
        auto previous_progress{get_progress(txn)};
        auto senders_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kSendersKey)};

        // This is next stage probably needing full history
        auto hashstate_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kHashStateKey)};

        if (previous_progress == senders_stage_progress) {
            // Nothing to process
            operation_ = OperationType::None;
            return ret;
        } else if (previous_progress > senders_stage_progress) {
            // Something bad had happened. Not possible execution stage is ahead of senders
            // Maybe we need to unwind ?
            std::string what{"Bad progress sequence. Execution stage progress " + std::to_string(previous_progress) +
                             " while Senders stage " + std::to_string(senders_stage_progress)};
            throw StageError(Stage::Result::kInvalidProgress, what);
        }

        std::unique_lock progress_lock(progress_mtx_);
        processed_blocks_ = 0;
        processed_transactions_ = 0;
        processed_gas_ = 0;
        lap_time_ = std::chrono::steady_clock::now();
        progress_lock.unlock();

        block_num_ = previous_progress + 1;
        BlockNum max_block_num{senders_stage_progress};
        BlockNum segment_width{senders_stage_progress - previous_progress};
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(block_num_),
                       "to", std::to_string(senders_stage_progress),
                       "span", std::to_string(segment_width)});
        }

        // Determine pruning thresholds on behalf of current db pruning mode and verify next stage(s) does not need
        // prune-able data
        BlockNum prune_history{node_settings_->prune_mode->history().value_from_head(senders_stage_progress)};
        BlockNum prune_receipts{node_settings_->prune_mode->receipts().value_from_head(senders_stage_progress)};
        if (hashstate_stage_progress) {
            prune_history = std::min(prune_history, hashstate_stage_progress - 1);
            prune_receipts = std::min(prune_receipts, hashstate_stage_progress - 1);
        }

        static constexpr size_t kCacheSize{5'000};
        BaselineAnalysisCache analysis_cache{kCacheSize};
        ObjectPool<EvmoneExecutionState> state_pool;

        prefetched_blocks_.clear();

        while (block_num_ <= max_block_num) {
            throw_if_stopping();
            const auto execution_result{execute_batch(txn,
                                                      max_block_num,
                                                      analysis_cache,
                                                      state_pool,
                                                      prune_history,
                                                      prune_receipts)};

            // If we return with success we must persist data
            // Though counterintuitive we also must persist on KInvalidBlock to allow subsequent unwind
            if (execution_result != Stage::Result::kSuccess &&
                execution_result != Stage::Result::kInvalidBlock) {
                throw StageError(execution_result);
            }

            // Persist forward and prune progresses
            update_progress(txn, block_num_);
            if (node_settings_->prune_mode->history().enabled() || node_settings_->prune_mode->receipts().enabled()) {
                db::stages::write_stage_prune_progress(*txn, db::stages::kExecutionKey, block_num_);
            }

            (void)commit_stopwatch.start(/*with_reset=*/true);
            txn.commit();
            auto [_, duration]{commit_stopwatch.stop()};
            log::Info(log_prefix_ + " commit", {"batch time", StopWatch::format(duration)});

            // If an invalid block returned now can throw
            if (execution_result == Stage::Result::kInvalidBlock) {
                ret = execution_result;
                break;
            }
            block_num_++;
        }

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
                   {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return ret;
}

void Execution::prefetch_blocks(db::RWTxn& txn, const BlockNum from, const BlockNum to) {
    std::unique_ptr<StopWatch> sw;
    if (log::test_verbosity(log::Level::kTrace)) {
        sw = std::make_unique<StopWatch>(/*auto_start=*/true);
    }

    assert(prefetched_blocks_.empty());

    const size_t count{std::min(static_cast<size_t>(to - from + 1), kMaxPrefetchedBlocks)};
    size_t num_read{0};

    db::Cursor canonicals(txn, db::table::kCanonicalHashes);
    Bytes starting_key{db::block_key(from)};
    if (canonicals.seek(db::to_slice(starting_key))) {
        BlockNum block_num{from};
        auto walk_function{[&](ByteView key, ByteView value) {
            BlockNum reached_block_num{endian::load_big_u64(key.data())};
            if (reached_block_num != block_num) {
                throw std::runtime_error("Bad canonical header sequence: expected " + std::to_string(block_num) +
                                         " got " + std::to_string(reached_block_num));
            } else if (value.length() != kHashLength) {
                throw std::runtime_error("Invalid value for hash in " +
                                         std::string(db::table::kCanonicalHashes.name) +
                                         " expected=" + std::to_string(kHashLength) +
                                         " got=" + std::to_string(value.length()));
            }

            const auto hash_ptr{value.data()};
            prefetched_blocks_.push_back();
            if (!db::read_block(*txn, std::span<const uint8_t, kHashLength>{hash_ptr, kHashLength}, block_num,
                                /*read_senders=*/true, prefetched_blocks_.back())) {
                throw std::runtime_error("Unable to read block " + std::to_string(block_num));
            }
            ++block_num;
        }};
        num_read = db::cursor_for_count(canonicals, walk_function, count);
    }

    if (num_read != count) {
        throw std::runtime_error("Missing block " + std::to_string(from + num_read));
    }

    if (sw) {
        auto [_, duration]{sw->lap()};
        log::Trace("Fetched blocks", {"size", std::to_string(num_read), "in", StopWatch::format(duration)});
    }
}

Stage::Result Execution::execute_batch(db::RWTxn& txn, BlockNum max_block_num, BaselineAnalysisCache& analysis_cache,
                                       ObjectPool<EvmoneExecutionState>& state_pool, BlockNum prune_history_threshold,
                                       BlockNum prune_receipts_threshold) {
    Stage::Result ret{Stage::Result::kSuccess};
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

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

        while (true) {
            if (prefetched_blocks_.empty()) {
                throw_if_stopping();
                prefetch_blocks(txn, block_num_, max_block_num);
            }

            const Block& block{prefetched_blocks_.front()};
            check_block_sequence(block.header.number, block_num_);

            // Log and abort check
            if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
                throw_if_stopping();
                log_time = now + 5s;
            }

            ExecutionProcessor processor(block, *consensus_engine_, buffer, node_settings_->chain_config.value());
            processor.evm().baseline_analysis_cache = &analysis_cache;
            processor.evm().state_pool = &state_pool;

            // TODO Add Tracer and collect call traces

            if (const auto res{processor.execute_and_write_block(receipts)}; res != ValidationResult::kOk) {
                // Persist work done so far
                if (block_num_ >= prune_receipts_threshold) {
                    buffer.insert_receipts(block_num_, receipts);
                }
                buffer.write_to_db();
                prefetched_blocks_.clear();

                // Notify sync_loop we need to unwind
                sync_context_->unwind_point.emplace(block_num_ - 1u);
                sync_context_->bad_block_hash.emplace(block.header.hash());

                // Display warning and return
                log::Warning(log_prefix_,
                             {"block", std::to_string(block_num_),
                              "hash", to_hex(block.header.hash().bytes, true),
                              "error", std::string(magic_enum::enum_name<ValidationResult>(res))});
                return Stage::Result::kInvalidBlock;
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

            prefetched_blocks_.pop_front();

            // Flush whole buffer if time to
            if (gas_batch_size >= gas_max_batch_size || block_num_ >= max_block_num) {
                log::Trace(log_prefix_, {"buffer", "state", "size", human_size(buffer.current_batch_state_size())});
                buffer.write_to_db();
                break;
            } else if (gas_history_size >= gas_max_history_size) {
                // or flush history only if needed
                log::Trace(log_prefix_, {"buffer", "history", "size", human_size(buffer.current_batch_state_size())});
                buffer.write_history_to_db();
                gas_history_size = 0;
            }

            ++block_num_;
        }

    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const rlp::DecodingError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "decoding error", std::string(ex.what())});
        return Stage::Result::kDecodingError;
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

Stage::Result Execution::unwind(db::RWTxn& txn) {
    static const db::MapConfig unwind_tables[5] = {
        db::table::kAccountChangeSet,  //
        db::table::kStorageChangeSet,  //
        db::table::kBlockReceipts,     //
        db::table::kLogs,              //
        db::table::kCallTraceSet       //
    };

    Stage::Result ret{Stage::Result::kSuccess};
    if (!sync_context_->unwind_point.has_value()) return ret;
    const BlockNum to{sync_context_->unwind_point.value()};

    operation_ = OperationType::Unwind;
    try {
        BlockNum previous_progress{db::stages::read_stage_progress(*txn, db::stages::kExecutionKey)};
        if (to >= previous_progress) {
            operation_ = OperationType::None;
            return Stage::Result::kSuccess;
        }

        operation_ = OperationType::Unwind;
        const BlockNum segment_width{previous_progress - to};
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(previous_progress),
                       "to", std::to_string(to),
                       "span", std::to_string(segment_width)});
        }

        {
            // Revert states
            db::Cursor plain_state_table(txn, db::table::kPlainState);
            db::Cursor plain_code_table(txn, db::table::kPlainCodeHash);
            db::Cursor account_changeset_table(txn, db::table::kAccountChangeSet);
            db::Cursor storage_changeset_table(txn, db::table::kStorageChangeSet);

            unwind_state_from_changeset(account_changeset_table, plain_state_table, plain_code_table, to);
            unwind_state_from_changeset(storage_changeset_table, plain_state_table, plain_code_table, to);
        }

        // Delete records which has keys greater than unwind point
        // Note erasing forward the start key is included that's why we increase unwind_point by 1
        Bytes start_key{db::block_key(to + 1)};
        for (const auto& map_config : unwind_tables) {
            db::Cursor unwind_cursor(txn, map_config);
            auto erased{db::cursor_erase(unwind_cursor, start_key, db::CursorMoveDirection::Forward)};
            log::Info() << "Erased " << erased << " records from " << map_config.name;
        }
        db::stages::write_stage_progress(*txn, db::stages::kExecutionKey, to);
        txn.commit();

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
                   {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return ret;
}

Stage::Result Execution::prune(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::Prune;

    std::unique_ptr<StopWatch> stop_watch;
    if (log::test_verbosity(log::Level::kTrace)) {
        stop_watch = std::make_unique<StopWatch>(true);
    }

    try {
        if (!node_settings_->prune_mode->history().enabled() &&
            !node_settings_->prune_mode->receipts().enabled() &&
            !node_settings_->prune_mode->call_traces().enabled()) {
            operation_ = OperationType::None;
            return ret;
        }

        BlockNum forward_progress{get_progress(txn)};
        BlockNum prune_progress{get_prune_progress(txn)};
        if (prune_progress >= forward_progress) {
            operation_ = OperationType::None;
            return ret;
        }

        const BlockNum segment_width{forward_progress - prune_progress};

        // Prune history of changes (changesets)
        if (const auto prune_threshold{node_settings_->prune_mode->history().value_from_head(forward_progress)}; prune_threshold) {
            if (segment_width > db::stages::kSmallBlockSegmentWidth) {
                log::Info(log_prefix_,
                          {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                           "source", "history",
                           "from", std::to_string(prune_progress),
                           "to", std::to_string(forward_progress),
                           "threshold", std::to_string(prune_threshold)});
            }

            auto key{db::block_key(prune_threshold)};
            size_t erased{0};
            db::Cursor source(txn, db::table::kAccountChangeSet);
            auto data{source.lower_bound(db::to_slice(key), /*throw_notfound=*/false)};
            while (data) {
                erased += source.count_multivalue();
                source.erase(/*whole_multivalue=*/true);
                data = source.to_previous(/*throw_notfound=*/false);
            }
            if (stop_watch) {
                const auto [_, duration] = stop_watch->lap();
                log::Trace(log_prefix_,
                           {"source", db::table::kAccountChangeSet.name,
                            "erased", std::to_string(erased),
                            "elapsed", StopWatch::format(duration)});
            }

            source.bind(txn, db::table::kStorageChangeSet);
            data = source.lower_bound(db::to_slice(key), /*throw_notfound=*/false);
            while (data) {
                auto data_value_view{db::from_slice(data.value)};
                if (endian::load_big_u64(data_value_view.data()) < prune_threshold) {
                    erased += source.count_multivalue();
                    source.erase(/*whole_multivalue=*/true);
                }
                data = source.to_previous(/*throw_notfound=*/false);
            }
            if (stop_watch) {
                const auto [_, duration] = stop_watch->lap();
                log::Trace(log_prefix_,
                           {"source", db::table::kStorageChangeSet.name,
                            "erased", std::to_string(erased),
                            "elapsed", StopWatch::format(duration)});
            }
        }

        // Prune receipts
        if (const auto prune_threshold{node_settings_->prune_mode->receipts().value_from_head(forward_progress)}; prune_threshold) {
            if (segment_width > db::stages::kSmallBlockSegmentWidth) {
                log::Info(log_prefix_,
                          {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                           "source", "receipts",
                           "from", std::to_string(prune_progress),
                           "to", std::to_string(forward_progress),
                           "threshold", std::to_string(prune_threshold)});
            }
            auto key{db::block_key(prune_threshold)};
            db::Cursor source(txn, db::table::kBlockReceipts);
            size_t erased = db::cursor_erase(source, key, db::CursorMoveDirection::Reverse);
            if (stop_watch) {
                const auto [_, duration] = stop_watch->lap();
                log::Trace(log_prefix_,
                           {"source", db::table::kBlockReceipts.name,
                            "erased", std::to_string(erased),
                            "elapsed", StopWatch::format(duration)});
            }

            source.bind(txn, db::table::kLogs);
            erased = db::cursor_erase(source, key, db::CursorMoveDirection::Reverse);
            if (stop_watch) {
                const auto [_, duration] = stop_watch->lap();
                log::Trace(log_prefix_,
                           {"source", db::table::kLogs.name,
                            "erased", std::to_string(erased),
                            "elapsed", StopWatch::format(duration)});
            }
        }

        // Prune call traces
        if (const auto prune_threshold{node_settings_->prune_mode->receipts().value_from_head(forward_progress)}; prune_threshold) {
            if (segment_width > db::stages::kSmallBlockSegmentWidth) {
                log::Info(log_prefix_,
                          {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                           "source", "call traces",
                           "from", std::to_string(prune_progress),
                           "to", std::to_string(forward_progress),
                           "threshold", std::to_string(prune_threshold)});
            }
            auto key{db::block_key(prune_threshold)};
            db::Cursor source(txn, db::table::kCallTraceSet);
            size_t erased = db::cursor_erase(source, key, db::CursorMoveDirection::Reverse);
            if (stop_watch) {
                const auto [_, duration] = stop_watch->lap();
                log::Trace(log_prefix_,
                           {"source", db::table::kCallTraceSet.name,
                            "erased", std::to_string(erased),
                            "elapsed", StopWatch::format(duration)});
            }
        }

        db::stages::write_stage_prune_progress(*txn, db::stages::kExecutionKey, forward_progress);
        txn.commit();

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
                   {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return ret;
}

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

    return {"block", std::to_string(block_num_), "blocks/s", std::to_string(speed_blocks),
            "txns/s", std::to_string(speed_transactions), "Mgas/s", std::to_string(speed_mgas)};
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
        if (const auto block_number{endian::load_big_u64(&key[0])}; block_number <= unwind_to) {
            break;
        }
        auto [new_key, new_value]{db::changeset_to_plainstate_format(key, value)};
        revert_state(new_key, new_value, plain_state_table, plain_code_table);
        src_data = source_changeset.to_previous(/*throw_notfound*/ false);
    }
}
}  // namespace silkworm::stagedsync
