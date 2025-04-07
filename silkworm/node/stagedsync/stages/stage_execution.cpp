// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stage_execution.hpp"

#include <span>
#include <stdexcept>

#include <magic_enum.hpp>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/execution/call_tracer.hpp>
#include <silkworm/core/execution/processor.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/state/account_codec.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/node/execution/block/block_executor.hpp>

namespace silkworm::stagedsync {

using namespace silkworm::db;
using namespace silkworm::datastore::kvdb;

Stage::Result Execution::forward(RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::kForward;
    try {
        throw_if_stopping();
        if (!rule_set_) {
            throw StageError(Stage::Result::kUnknownProtocolRuleSet);
        }

        StopWatch commit_stopwatch;
        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        const auto senders_stage_progress{stages::read_stage_progress(txn, stages::kSendersKey)};

        // This is next stage probably needing full history
        const auto hashstate_stage_progress{stages::read_stage_progress(txn, stages::kHashStateKey)};

        if (previous_progress == senders_stage_progress) {
            // Nothing to process
            operation_ = OperationType::kNone;
            return ret;
        }
        if (previous_progress > senders_stage_progress) {
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
        const auto stop_at_block = Environment::get_stop_at_block();
        const BlockNum max_block_num{stop_at_block ? *stop_at_block : senders_stage_progress};
        const BlockNum segment_width{max_block_num - previous_progress};
        if (segment_width > stages::kSmallBlockSegmentWidth) {
            SILK_INFO_M(log_prefix_, {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                                      "from", std::to_string(previous_progress),
                                      "to", std::to_string(max_block_num),
                                      "span", std::to_string(segment_width)});
        }

        // Determine pruning thresholds on behalf of current db pruning mode and verify next stage(s) does not need
        // prune-able data
        BlockNum prune_history{prune_mode_.history().value_from_head(max_block_num)};
        BlockNum prune_receipts{prune_mode_.receipts().value_from_head(max_block_num)};
        BlockNum prune_call_traces{prune_mode_.call_traces().value_from_head(max_block_num)};
        if (hashstate_stage_progress) {
            prune_history = std::min(prune_history, hashstate_stage_progress - 1);
            prune_receipts = std::min(prune_receipts, hashstate_stage_progress - 1);
            prune_call_traces = std::min(prune_call_traces, hashstate_stage_progress - 1);
        }

        static constexpr size_t kCacheSize{5'000};
        AnalysisCache analysis_cache{kCacheSize};

        prefetched_blocks_.clear();

        while (block_num_ <= max_block_num) {
            throw_if_stopping();
            const auto execution_result{execute_batch(txn, max_block_num, analysis_cache,
                                                      prune_history, prune_receipts, prune_call_traces)};

            // If we return with success we must persist data. Though counterintuitive, we must also persist on
            // kInvalidBlock to save good progress done so far: the subsequent unwind will remove last invalid updates
            if (execution_result != Stage::Result::kSuccess && execution_result != Stage::Result::kInvalidBlock) {
                throw StageError(execution_result);
            }

            // Persist forward and prune progresses
            update_progress(txn, block_num_);
            if (prune_mode_.history().enabled() || prune_mode_.receipts().enabled()) {
                stages::write_stage_prune_progress(txn, stages::kExecutionKey, block_num_);
            }

            (void)commit_stopwatch.start(/*with_reset=*/true);
            txn.commit_and_renew();
            auto [_, duration]{commit_stopwatch.stop()};
            SILK_INFO_M(log_prefix_ + " commit", {"batch time", StopWatch::format(duration)});

            // If we got an invalid block, now after persisting we can exit
            if (execution_result == Stage::Result::kInvalidBlock) {
                ret = execution_result;
                break;
            }
            ++block_num_;
        }

    } catch (const StageError& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const mdbx::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const std::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::kNone;
    return ret;
}

void Execution::prefetch_blocks(RWTxn& txn, const BlockNum from, const BlockNum to) {
    std::unique_ptr<StopWatch> sw;
    if (log::test_verbosity(log::Level::kTrace)) {
        sw = std::make_unique<StopWatch>(/*auto_start=*/true);
    }

    SILKWORM_ASSERT(prefetched_blocks_.empty());

    const size_t count{std::min(static_cast<size_t>(to - from + 1), kMaxPrefetchedBlocks)};
    size_t num_read{0};

    DataModel data_model = data_model_factory_(txn);
    auto canonicals = txn.ro_cursor(table::kCanonicalHashes);
    Bytes starting_key{block_key(from)};
    if (canonicals->seek(to_slice(starting_key))) {
        BlockNum block_num{from};
        auto walk_function{[&](ByteView key, ByteView value) {
            BlockNum reached_block_num{endian::load_big_u64(key.data())};
            if (reached_block_num != block_num) {
                throw std::runtime_error("Bad canonical header sequence: expected " + std::to_string(block_num) +
                                         " got " + std::to_string(reached_block_num));
            }
            if (value.size() != kHashLength) {
                throw std::runtime_error("Invalid value for hash in " +
                                         std::string(table::kCanonicalHashes.name) +
                                         " expected=" + std::to_string(kHashLength) +
                                         " got=" + std::to_string(value.size()));
            }

            const auto hash_ptr{value.data()};
            prefetched_blocks_.push_back();
            if (!data_model.read_block(std::span<const uint8_t, kHashLength>{hash_ptr, kHashLength}, block_num,
                                       /*read_senders=*/true, prefetched_blocks_.back())) {
                throw std::runtime_error("Unable to read block " + std::to_string(block_num));
            }
            ++block_num;
        }};
        num_read = cursor_for_count(*canonicals, walk_function, count);
    }

    if (num_read != count) {
        throw std::runtime_error("Missing block " + std::to_string(from + num_read));
    }

    if (sw) {
        auto [_, duration]{sw->lap()};
        SILK_TRACE_M("Fetched blocks", {"size", std::to_string(num_read), "in", StopWatch::format(duration)});
    }
}

Stage::Result Execution::execute_batch(RWTxn& txn, BlockNum max_block_num, AnalysisCache& analysis_cache,
                                       BlockNum prune_history_threshold, BlockNum prune_receipts_threshold,
                                       BlockNum prune_call_traces_threshold) {
    Result ret{Result::kSuccess};
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    try {
        Buffer buffer{txn, std::make_unique<BufferFullDataModel>(data_model_factory_(txn))};
        buffer.set_prune_history_threshold(prune_history_threshold);
        buffer.set_memory_limit(batch_size_);

        std::vector<Receipt> receipts;

        {
            std::unique_lock progress_lock(progress_mtx_);
            lap_time_ = std::chrono::steady_clock::now();
        }

        while (block_num_ <= max_block_num) {
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

            const bool write_receipts = block_num_ >= prune_receipts_threshold;
            const bool write_traces = block_num_ >= prune_call_traces_threshold;
            static constexpr bool kWriteChangeSets = true;

            execution::block::BlockExecutor executor{&chain_config_, write_receipts, write_traces, kWriteChangeSets};
            try {
                if (const ValidationResult res = executor.execute_single(block, buffer, analysis_cache); res != ValidationResult::kOk) {
                    // Flush work done so far not to lose progress up to the previous valid block and to correctly trigger unwind
                    // This requires to commit in Execution::forward also for kInvalidBlock: unwind will remove last invalid block updates
                    if (write_receipts) {
                        buffer.insert_receipts(block_num_, receipts);
                    }
                    buffer.write_to_db();

                    // Notify sync_loop we need to unwind
                    sync_context_->unwind_point.emplace(block_num_ - 1u);
                    sync_context_->bad_block_hash.emplace(block.header.hash());

                    SILK_ERROR_M(log_prefix_, {"block", std::to_string(block_num_),
                                               "hash", to_hex(block.header.hash().bytes, true),
                                               "error", std::string(magic_enum::enum_name<ValidationResult>(res))});

                    prefetched_blocks_.clear();  // Must stay here to keep `block` reference valid
                    return Result::kInvalidBlock;
                }

            } catch (const Buffer::MemoryLimitError&) {
                // batch done
                break;
            }

            // Stats
            std::unique_lock progress_lock(progress_mtx_);
            ++processed_blocks_;
            processed_transactions_ += block.transactions.size();
            processed_gas_ += block.header.gas_used;
            progress_lock.unlock();

            prefetched_blocks_.pop_front();
            ++block_num_;
        }

        // update block_num_ to point to the last successfully executed block
        --block_num_;

        SILK_TRACE_M(log_prefix_, {"buffer", "state", "size", human_size(buffer.current_batch_state_size())});
        buffer.write_to_db();

    } catch (const StageError& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const mdbx::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const DecodingException& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "decoding error", std::string(ex.what())});
        return Stage::Result::kDecodingError;
    } catch (const std::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    return ret;
}

Stage::Result Execution::unwind(RWTxn& txn) {
    static const MapConfig kUnwindTables[5] = {
        table::kAccountChangeSet,
        table::kStorageChangeSet,
        table::kBlockReceipts,
        table::kLogs,
        table::kCallTraceSet,
    };

    Stage::Result ret{Stage::Result::kSuccess};
    if (!sync_context_->unwind_point.has_value()) return ret;
    const BlockNum to{sync_context_->unwind_point.value()};

    operation_ = OperationType::kUnwind;
    try {
        BlockNum previous_progress{stages::read_stage_progress(txn, stages::kExecutionKey)};
        if (to >= previous_progress) {
            operation_ = OperationType::kNone;
            return Stage::Result::kSuccess;
        }

        operation_ = OperationType::kUnwind;
        const BlockNum segment_width{previous_progress - to};
        if (segment_width > stages::kSmallBlockSegmentWidth) {
            SILK_INFO_M(log_prefix_, {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                                      "from", std::to_string(previous_progress),
                                      "to", std::to_string(to),
                                      "span", std::to_string(segment_width)});
        }

        {
            // Revert states
            auto plain_state_cursor = txn.rw_cursor_dup_sort(table::kPlainState);
            auto plain_code_cursor = txn.rw_cursor(table::kPlainCodeHash);
            auto account_changeset_cursor = txn.ro_cursor_dup_sort(table::kAccountChangeSet);
            auto storage_changeset_cursor = txn.ro_cursor_dup_sort(table::kStorageChangeSet);

            unwind_state_from_changeset(*account_changeset_cursor, *plain_state_cursor, *plain_code_cursor, to);
            unwind_state_from_changeset(*storage_changeset_cursor, *plain_state_cursor, *plain_code_cursor, to);
        }

        // Delete records which has keys greater than unwind point
        // Note erasing forward the start key is included that's why we increase unwind_point by 1
        Bytes start_key{block_key(to + 1)};
        for (const auto& map_config : kUnwindTables) {
            auto unwind_cursor = txn.rw_cursor(map_config);
            auto erased{cursor_erase(*unwind_cursor, start_key, CursorMoveDirection::kForward)};
            SILK_INFO << "Erased " << erased << " records from " << map_config.name;
        }
        stages::write_stage_progress(txn, stages::kExecutionKey, to);
        txn.commit_and_renew();

    } catch (const StageError& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const mdbx::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const std::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::kNone;
    return ret;
}

Stage::Result Execution::prune(RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::kPrune;

    std::unique_ptr<StopWatch> stop_watch;
    if (log::test_verbosity(log::Level::kTrace)) {
        stop_watch = std::make_unique<StopWatch>(true);
    }

    try {
        if (!prune_mode_.history().enabled() &&
            !prune_mode_.receipts().enabled() &&
            !prune_mode_.call_traces().enabled()) {
            operation_ = OperationType::kNone;
            return ret;
        }

        BlockNum forward_progress{get_progress(txn)};
        BlockNum prune_progress{get_prune_progress(txn)};
        if (prune_progress >= forward_progress) {
            operation_ = OperationType::kNone;
            return ret;
        }

        const BlockNum segment_width{forward_progress - prune_progress};

        // Prune history of changes (changesets)
        if (const auto prune_threshold{prune_mode_.history().value_from_head(forward_progress)}; prune_threshold) {
            if (segment_width > stages::kSmallBlockSegmentWidth) {
                SILK_INFO_M(log_prefix_, {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                                          "source", "history",
                                          "from", std::to_string(prune_progress),
                                          "to", std::to_string(forward_progress),
                                          "threshold", std::to_string(prune_threshold)});
            }

            auto key{block_key(prune_threshold)};
            size_t erased{0};
            auto source = txn.rw_cursor_dup_sort(table::kAccountChangeSet);
            auto data{source->lower_bound(to_slice(key), /*throw_notfound=*/false)};
            while (data) {
                erased += source->count_multivalue();
                source->erase(/*whole_multivalue=*/true);
                data = source->to_previous(/*throw_notfound=*/false);
            }
            if (stop_watch) {
                const auto [_, duration] = stop_watch->lap();
                SILK_TRACE_M(log_prefix_, {"source", table::kAccountChangeSet.name,
                                           "erased", std::to_string(erased),
                                           "elapsed", StopWatch::format(duration)});
            }

            source->bind(txn, table::kStorageChangeSet);
            data = source->lower_bound(to_slice(key), /*throw_notfound=*/false);
            while (data) {
                auto data_value_view{from_slice(data.value)};
                if (endian::load_big_u64(data_value_view.data()) < prune_threshold) {
                    erased += source->count_multivalue();
                    source->erase(/*whole_multivalue=*/true);
                }
                data = source->to_previous(/*throw_notfound=*/false);
            }
            if (stop_watch) {
                const auto [_, duration] = stop_watch->lap();
                SILK_TRACE_M(log_prefix_, {"source", table::kStorageChangeSet.name,
                                           "erased", std::to_string(erased),
                                           "elapsed", StopWatch::format(duration)});
            }
        }

        // Prune receipts
        if (const auto prune_threshold{prune_mode_.receipts().value_from_head(forward_progress)}; prune_threshold) {
            if (segment_width > stages::kSmallBlockSegmentWidth) {
                SILK_INFO_M(log_prefix_, {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                                          "source", "receipts",
                                          "from", std::to_string(prune_progress),
                                          "to", std::to_string(forward_progress),
                                          "threshold", std::to_string(prune_threshold)});
            }
            auto key{block_key(prune_threshold)};
            auto source = txn.rw_cursor(table::kBlockReceipts);
            size_t erased = cursor_erase(*source, key, CursorMoveDirection::kReverse);
            if (stop_watch) {
                const auto [_, duration] = stop_watch->lap();
                SILK_TRACE_M(log_prefix_, {"source", table::kBlockReceipts.name,
                                           "erased", std::to_string(erased),
                                           "elapsed", StopWatch::format(duration)});
            }

            source->bind(txn, table::kLogs);
            erased = cursor_erase(*source, key, CursorMoveDirection::kReverse);
            if (stop_watch) {
                const auto [_, duration] = stop_watch->lap();
                SILK_TRACE_M(log_prefix_, {"source", table::kLogs.name,
                                           "erased", std::to_string(erased),
                                           "elapsed", StopWatch::format(duration)});
            }
        }

        // Prune call traces
        if (const auto prune_threshold{prune_mode_.call_traces().value_from_head(forward_progress)}; prune_threshold) {
            if (segment_width > stages::kSmallBlockSegmentWidth) {
                SILK_INFO_M(log_prefix_, {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                                          "source", "call traces",
                                          "from", std::to_string(prune_progress),
                                          "to", std::to_string(forward_progress),
                                          "threshold", std::to_string(prune_threshold)});
            }
            auto key{block_key(prune_threshold)};
            auto source = txn.rw_cursor_dup_sort(table::kCallTraceSet);
            size_t erased = cursor_erase(*source, key, CursorMoveDirection::kReverse);
            if (stop_watch) {
                const auto [_, duration] = stop_watch->lap();
                SILK_TRACE_M(log_prefix_, {"source", table::kCallTraceSet.name,
                                           "erased", std::to_string(erased),
                                           "elapsed", StopWatch::format(duration)});
            }
        }

        stages::write_stage_prune_progress(txn, stages::kExecutionKey, forward_progress);
        txn.commit_and_renew();

    } catch (const StageError& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<Stage::Result>(ex.err());
    } catch (const mdbx::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kDbError;
    } catch (const std::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = Stage::Result::kUnexpectedError;
    } catch (...) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", "undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::kNone;
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

void Execution::revert_state(ByteView key, ByteView value, RWCursorDupSort& plain_state_table,
                             RWCursor& plain_code_table) {
    if (key.size() == kAddressLength) {
        if (!value.empty()) {
            const auto account_res = db::state::AccountCodec::from_encoded_storage(value);
            SILKWORM_ASSERT(account_res);
            Account account{*account_res};
            // Recover the account contract hash
            if (account.incarnation > 0 && account.code_hash == kEmptyHash) {
                Bytes code_hash_key(kAddressLength + kIncarnationLength, '\0');
                std::memcpy(&code_hash_key[0], &key[0], kAddressLength);
                endian::store_big_u64(&code_hash_key[kAddressLength], account.incarnation);
                const auto new_code_hash = plain_code_table.find(to_slice(code_hash_key), /*throw_notfound=*/false);
                if (new_code_hash.done) {
                    SILKWORM_ASSERT(new_code_hash.value.size() >= kHashLength);
                    std::memcpy(&account.code_hash.bytes[0], new_code_hash.value.data(), kHashLength);
                }
            }
            // cleaning up contract codes
            auto state_account_encoded{plain_state_table.find(to_slice(key), /*throw_notfound=*/false)};
            if (state_account_encoded) {
                const auto state_incarnation = db::state::AccountCodec::incarnation_from_encoded_storage(from_slice(state_account_encoded.value));
                SILKWORM_ASSERT(state_incarnation);
                // Cleanup each code incarnation
                for (uint64_t i = *state_incarnation; i > account.incarnation; --i) {
                    Bytes storage_key = storage_prefix(key, i);
                    plain_code_table.erase(to_slice(storage_key));
                }
            }
            Bytes new_encoded_account = db::state::AccountCodec::encode_for_storage(account);
            plain_state_table.erase(to_slice(key), /*whole_multivalue=*/true);
            plain_state_table.upsert(to_slice(key), to_slice(new_encoded_account));
        } else {
            plain_state_table.erase(to_slice(key));
        }
        return;
    }
    auto location{key.substr(kAddressLength + kIncarnationLength)};
    auto key1{key.substr(0, kAddressLength + kIncarnationLength)};
    if (find_value_suffix(plain_state_table, key1, location) != std::nullopt) {
        plain_state_table.erase();
    }
    if (!value.empty()) {
        Bytes data{location};
        data.append(value);
        plain_state_table.upsert(to_slice(key1), to_slice(data));
    }
}

void Execution::unwind_state_from_changeset(ROCursor& source_changeset, RWCursorDupSort& plain_state_table,
                                            RWCursor& plain_code_table, BlockNum unwind_to) {
    auto src_data{source_changeset.to_last(/*throw_notfound*/ false)};
    while (src_data) {
        auto key(from_slice(src_data.key));
        auto value(from_slice(src_data.value));
        if (const auto block_num{endian::load_big_u64(&key[0])}; block_num <= unwind_to) {
            break;
        }
        auto [new_key, new_value]{changeset_to_plainstate_format(key, value)};
        revert_state(new_key, new_value, plain_state_table, plain_code_table);
        src_data = source_changeset.to_previous(/*throw_notfound*/ false);
    }
}

}  // namespace silkworm::stagedsync
