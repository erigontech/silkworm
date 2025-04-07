// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stage_call_trace_index.hpp"

#include <magic_enum.hpp>

namespace silkworm::stagedsync {

using namespace silkworm::db;
using namespace silkworm::datastore::kvdb;

CallTraceIndex::CallTraceIndex(SyncContext* sync_context,
                               size_t batch_size,
                               datastore::etl::CollectorSettings etl_settings,
                               BlockAmount prune_mode)
    : Stage(sync_context, stages::kCallTracesKey),
      batch_size_{batch_size},
      etl_settings_{std::move(etl_settings)},
      prune_mode_{prune_mode} {}

Stage::Result CallTraceIndex::forward(RWTxn& txn) {
    Stage::Result result{Stage::Result::kSuccess};

    operation_ = OperationType::kForward;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        auto previous_progress{get_progress(txn)};
        const auto target_progress{stages::read_stage_progress(txn, stages::kExecutionKey)};
        if (previous_progress == target_progress) {
            // Nothing to process
            operation_ = OperationType::kNone;
            return result;
        }
        if (previous_progress > target_progress) {
            // Something bad had happened.  Maybe we need to unwind ?
            throw StageError(Stage::Result::kInvalidProgress,
                             "CallTraceIndex progress " + std::to_string(previous_progress) +
                                 " greater than Execution progress " + std::to_string(target_progress));
        }

        reset_log_progress();
        const BlockNum segment_width{target_progress - previous_progress};
        if (segment_width > stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(previous_progress),
                       "to", std::to_string(target_progress),
                       "span", std::to_string(segment_width)});
        }

        // If this is first time and prune mode is set, do not process all blocks rather only what is needed
        if (prune_mode_.enabled() && !previous_progress) {
            previous_progress = prune_mode_.value_from_head(target_progress);
        }

        if (previous_progress < target_progress) {
            forward_impl(txn, previous_progress, target_progress);
        }

        reset_log_progress();
        update_progress(txn, target_progress);
        txn.commit_and_renew();
    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = static_cast<Stage::Result>(ex.err());
    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = Stage::Result::kDbError;
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = Stage::Result::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        result = Stage::Result::kUnexpectedError;
    }

    call_from_collector_.reset();
    call_to_collector_.reset();
    operation_ = OperationType::kNone;

    return result;
}

Stage::Result CallTraceIndex::unwind(RWTxn& txn) {
    Stage::Result result{Stage::Result::kSuccess};

    if (!sync_context_->unwind_point.has_value()) {
        return result;
    }
    const BlockNum to{sync_context_->unwind_point.value()};

    operation_ = OperationType::kUnwind;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        const auto execution_stage_progress{stages::read_stage_progress(txn, stages::kExecutionKey)};
        if (previous_progress <= to || execution_stage_progress <= to) {
            // Nothing to process
            operation_ = OperationType::kNone;
            return result;
        }

        reset_log_progress();
        const BlockNum segment_width{previous_progress - to};
        if (segment_width > stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(previous_progress),
                       "to", std::to_string(to),
                       "span", std::to_string(segment_width)});
        }

        if (previous_progress && previous_progress > to) {
            unwind_impl(txn, previous_progress, to);
        }

        reset_log_progress();
        update_progress(txn, to);
        txn.commit_and_renew();
    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = static_cast<Stage::Result>(ex.err());
    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = Stage::Result::kDbError;
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = Stage::Result::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        result = Stage::Result::kUnexpectedError;
    }

    call_from_collector_.reset();
    call_to_collector_.reset();
    operation_ = OperationType::kNone;

    return result;
}

Stage::Result CallTraceIndex::prune(RWTxn& txn) {
    Stage::Result result{Stage::Result::kSuccess};

    operation_ = OperationType::kPrune;
    try {
        throw_if_stopping();

        if (!prune_mode_.enabled()) {
            operation_ = OperationType::kNone;
            return result;
        }

        const auto forward_progress{get_progress(txn)};
        const auto prune_progress{get_prune_progress(txn)};
        if (prune_progress >= forward_progress) {
            operation_ = OperationType::kNone;
            return result;
        }

        // Need to erase all info below this threshold. If threshold is zero we don't have anything to prune
        const auto prune_threshold{prune_mode_.value_from_head(forward_progress)};
        if (!prune_threshold) {
            operation_ = OperationType::kNone;
            return result;
        }

        reset_log_progress();
        const BlockNum segment_width{forward_progress - prune_progress};
        if (segment_width > stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(prune_progress),
                       "to", std::to_string(forward_progress),
                       "threshold", std::to_string(prune_threshold)});
        }

        if (!prune_progress || prune_progress < forward_progress) {
            prune_impl(txn, prune_threshold, table::kCallFromIndex);
            prune_impl(txn, prune_threshold, table::kCallToIndex);
        }

        reset_log_progress();
        stages::write_stage_prune_progress(txn, stage_name_, forward_progress);
        txn.commit_and_renew();
    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = static_cast<Stage::Result>(ex.err());
    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = Stage::Result::kDbError;
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = Stage::Result::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        result = Stage::Result::kUnexpectedError;
    }

    call_from_collector_.reset();
    call_to_collector_.reset();
    operation_ = OperationType::kNone;

    return result;
}

void CallTraceIndex::forward_impl(RWTxn& txn, const BlockNum from, const BlockNum to) {
    const MapConfig source_config{table::kCallTraceSet};

    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::kForward;
    loading_ = false;
    call_from_collector_ = std::make_unique<Collector>(etl_settings_);
    call_to_collector_ = std::make_unique<Collector>(etl_settings_);
    current_source_ = std::string(source_config.name);
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();

    // Into etl collectors
    collect_bitmaps_from_call_traces(txn, source_config, from, to);

    log_lck.lock();
    loading_ = true;
    current_key_.clear();
    current_target_ = table::kCallFromIndex.name;
    index_loader_ = std::make_unique<bitmap::IndexLoader>(table::kCallFromIndex);
    log_lck.unlock();

    index_loader_->merge_bitmaps(txn, kAddressLength, call_from_collector_.get());

    log_lck.lock();
    current_key_.clear();
    current_target_ = table::kCallToIndex.name;
    index_loader_ = std::make_unique<bitmap::IndexLoader>(table::kCallToIndex);
    log_lck.unlock();

    index_loader_->merge_bitmaps(txn, kAddressLength, call_to_collector_.get());

    log_lck.lock();
    loading_ = false;
    current_target_.clear();
    index_loader_.reset();
    log_lck.unlock();
}

void CallTraceIndex::unwind_impl(RWTxn& txn, BlockNum from, BlockNum to) {
    const MapConfig source_config{table::kCallTraceSet};

    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::kUnwind;
    loading_ = false;
    current_source_ = std::string(source_config.name);
    current_key_.clear();
    log_lck.unlock();

    std::map<Bytes, bool> call_from_keys;
    std::map<Bytes, bool> call_to_keys;
    collect_unique_keys_from_call_traces(txn, source_config, from, to, call_from_keys, call_to_keys);

    log_lck.lock();
    current_target_ = table::kCallFromIndex.name;
    index_loader_ = std::make_unique<bitmap::IndexLoader>(table::kCallFromIndex);
    log_lck.unlock();

    index_loader_->unwind_bitmaps(txn, to, call_from_keys);

    log_lck.lock();
    current_target_ = table::kCallToIndex.name;
    index_loader_ = std::make_unique<bitmap::IndexLoader>(table::kCallToIndex);
    log_lck.unlock();

    index_loader_->unwind_bitmaps(txn, to, call_to_keys);

    log_lck.lock();
    index_loader_.reset();
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();
}

void CallTraceIndex::collect_bitmaps_from_call_traces(RWTxn& txn, const MapConfig& source_config,
                                                      BlockNum from, BlockNum to) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    const BlockNum max_block_num{to};
    BlockNum reached_block_num{0};

    absl::btree_map<Bytes, roaring::Roaring64Map> call_from_bitmaps;
    absl::btree_map<Bytes, roaring::Roaring64Map> call_to_bitmaps;
    size_t call_from_bitmaps_size{0};
    size_t call_to_bitmaps_size{0};
    uint16_t call_from_flush_count{0};
    uint16_t call_to_flush_count{0};

    const auto start_key{block_key(from + 1)};
    const auto source = txn.ro_cursor(source_config);
    auto source_data{source->lower_bound(to_slice(start_key), false)};
    while (source_data) {
        reached_block_num = endian::load_big_u64(static_cast<uint8_t*>(source_data.key.data()));
        if (reached_block_num > max_block_num) break;

        // Log and abort check
        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            std::unique_lock log_lck(sl_mutex_);
            current_key_ = std::to_string(reached_block_num);
            log_time = now + 5s;
        }

        // Check expected value format
        ByteView value{static_cast<uint8_t*>(source_data.value.data()), source_data.value.length()};
        ensure(value.size() == kAddressLength + 1, [&] { return "Unexpected value in CallTraceSet: " + to_hex(value); });

        // Decode value as address|from_or_to_or_both and distribute it to the 2 bitmaps
        Bytes address{value.substr(0, kAddressLength)};
        if (value[kAddressLength] & 1) {
            auto it{call_from_bitmaps.find(address)};
            if (it == call_from_bitmaps.end()) {
                it = call_from_bitmaps.emplace(address, roaring::Roaring64Map()).first;
                call_from_bitmaps_size += kAddressLength + sizeof(uint64_t);
            }
            it->second.add(reached_block_num);
            call_from_bitmaps_size += sizeof(uint64_t);
        }
        if (value[kAddressLength] & 2) {
            auto it{call_to_bitmaps.find(address)};
            if (it == call_to_bitmaps.end()) {
                it = call_to_bitmaps.emplace(address, roaring::Roaring64Map()).first;
                call_to_bitmaps_size += kAddressLength + sizeof(uint64_t);
            }
            it->second.add(reached_block_num);
            call_to_bitmaps_size += sizeof(uint64_t);
        }

        // Flush bitmaps batch by batch
        if (call_from_bitmaps_size > batch_size_) {
            bitmap::IndexLoader::flush_bitmaps_to_etl(call_from_bitmaps,
                                                      call_from_collector_.get(),
                                                      call_from_flush_count++);
            call_from_bitmaps_size = 0;
        }

        if (call_to_bitmaps_size > batch_size_) {
            bitmap::IndexLoader::flush_bitmaps_to_etl(call_to_bitmaps,
                                                      call_to_collector_.get(),
                                                      call_to_flush_count++);
            call_to_bitmaps_size = 0;
        }

        source_data = source->to_next(/*throw_notfound=*/false);
    }

    // Flush remaining portion of bitmaps (if any)
    bitmap::IndexLoader::flush_bitmaps_to_etl(call_from_bitmaps, call_from_collector_.get(), call_from_flush_count);
    bitmap::IndexLoader::flush_bitmaps_to_etl(call_to_bitmaps, call_to_collector_.get(), call_to_flush_count);
}

void CallTraceIndex::collect_unique_keys_from_call_traces(RWTxn& txn, const MapConfig& source_config,
                                                          BlockNum from, BlockNum to,
                                                          std::map<Bytes, bool>& senders, std::map<Bytes, bool>& receivers) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    BlockNum expected_block_num{std::min(from, to) + 1};
    const BlockNum max_block_num{std::max(from, to)};
    BlockNum reached_block_num{0};

    const auto start_key{block_key(expected_block_num)};
    const auto source = txn.ro_cursor(source_config);
    auto source_data{source->lower_bound(to_slice(start_key), false)};
    while (source_data) {
        reached_block_num = endian::load_big_u64(static_cast<uint8_t*>(source_data.key.data()));
        if (reached_block_num > max_block_num) break;

        // Log and abort check
        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            std::unique_lock log_lck(sl_mutex_);
            current_key_ = std::to_string(reached_block_num);
            log_time = now + 5s;
        }

        // Check expected value format
        ByteView value{static_cast<uint8_t*>(source_data.value.data()), source_data.value.length()};
        ensure(value.size() == kAddressLength + 1, [&] { return "Unexpected value in CallTraceSet: " + to_hex(value); });

        // Decode value as address|from_or_to_or_both
        Bytes address{value.substr(0, kAddressLength)};
        if (value[kAddressLength] & 1) {
            (void)senders.try_emplace(address, false);
        }
        if (value[kAddressLength] & 2) {
            (void)receivers.try_emplace(address, false);
        }

        source_data = source->to_next(/*throw_notfound=*/false);
    }
}

void CallTraceIndex::prune_impl(RWTxn& txn, BlockNum threshold, const MapConfig& target) {
    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::kPrune;
    loading_ = false;
    current_source_ = target.name;
    current_target_ = current_source_;
    current_key_.clear();
    index_loader_ = std::make_unique<bitmap::IndexLoader>(target);
    log_lck.unlock();

    index_loader_->prune_bitmaps(txn, threshold);

    log_lck.lock();
    index_loader_.reset();
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();
}

std::vector<std::string> CallTraceIndex::get_log_progress() {
    std::vector<std::string> ret{"op", std::string(magic_enum::enum_name<OperationType>(operation_))};
    std::unique_lock log_lck(sl_mutex_);
    if (current_source_.empty() && current_target_.empty()) {
        ret.insert(ret.end(), {"db", "waiting ..."});
    } else {
        switch (operation_) {
            case OperationType::kForward:
                if (loading_) {
                    if (current_target_ == table::kCallFromIndex.name && call_from_collector_) {
                        current_key_ = abridge(call_from_collector_->get_load_key(), kAddressLength);
                    } else if (current_target_ == table::kCallToIndex.name && call_to_collector_) {
                        current_key_ = abridge(call_to_collector_->get_load_key(), kAddressLength);
                    } else {
                        current_key_.clear();
                    }
                    ret.insert(ret.end(), {"from", "ETL", "to", current_target_, "key", current_key_});
                } else {
                    ret.insert(ret.end(), {"from", current_source_, "to", "ETL", "key", current_key_});
                }
                break;
            case OperationType::kUnwind:
                if (index_loader_) {
                    current_key_ = index_loader_->get_current_key();
                    ret.insert(ret.end(), {"from", "ETL", "to", current_target_, "key", current_key_});
                } else {
                    ret.insert(ret.end(), {"from", current_source_, "to", "ETL", "key", current_key_});
                }
                break;
            case OperationType::kPrune:
                if (index_loader_) {
                    current_key_ = index_loader_->get_current_key();
                    ret.insert(ret.end(), {"to", current_target_, "key", current_key_});
                } else {
                    ret.insert(ret.end(), {"to", current_target_, current_key_});
                }
                break;
            default:
                ret.insert(ret.end(), {"from", current_source_, "key", current_key_});
        }
    }
    return ret;
}

void CallTraceIndex::reset_log_progress() {
    std::unique_lock log_lck(sl_mutex_);
    loading_ = false;
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
}

}  // namespace silkworm::stagedsync
