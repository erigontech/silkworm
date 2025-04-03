// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stage_history_index.hpp"

#include <magic_enum.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/endian.hpp>

namespace silkworm::stagedsync {

using namespace silkworm::db;
using silkworm::datastore::kvdb::from_slice;
using silkworm::datastore::kvdb::to_slice;
namespace bitmap {
    using namespace silkworm::datastore::kvdb::bitmap;
}

Stage::Result HistoryIndex::forward(RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::kForward;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        auto previous_progress_accounts{stages::read_stage_progress(txn, stages::kAccountHistoryIndexKey)};
        auto previous_progress_storage{stages::read_stage_progress(txn, stages::kStorageHistoryIndexKey)};
        const auto target_progress{stages::read_stage_progress(txn, stages::kExecutionKey)};
        if (previous_progress == target_progress) {
            // Nothing to process
            operation_ = OperationType::kNone;
            return ret;
        }
        if (previous_progress > target_progress) {
            // Something bad had happened.  Maybe we need to unwind ?
            throw StageError(Stage::Result::kInvalidProgress,
                             "HistoryIndex progress " + std::to_string(previous_progress) +
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

        // If this is first time we forward AND we have "prune history" set
        // do not process all blocks rather only what is needed
        if (prune_mode_history_.enabled()) {
            if (!previous_progress_accounts)
                previous_progress_accounts = prune_mode_history_.value_from_head(target_progress);
            if (!previous_progress_storage)
                previous_progress_storage = prune_mode_history_.value_from_head(target_progress);
        }

        collector_ = std::make_unique<datastore::kvdb::Collector>(etl_settings_);
        if (previous_progress_accounts < target_progress) {
            success_or_throw(forward_impl(txn, previous_progress_accounts, target_progress, false));
            txn.commit_and_renew();
        }
        if (previous_progress_storage < target_progress) {
            success_or_throw(forward_impl(txn, previous_progress_storage, target_progress, true));
            txn.commit_and_renew();
        }
        reset_log_progress();
        update_progress(txn, target_progress);
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

    collector_.reset();
    operation_ = OperationType::kNone;
    return is_stopping() ? Stage::Result::kAborted : ret;
}

Stage::Result HistoryIndex::unwind(RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};

    if (!sync_context_->unwind_point.has_value()) return ret;
    const BlockNum to{sync_context_->unwind_point.value()};

    operation_ = OperationType::kUnwind;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        const auto previous_progress_accounts{
            stages::read_stage_progress(txn, stages::kAccountHistoryIndexKey)};
        const auto previous_progress_storage{
            stages::read_stage_progress(txn, stages::kStorageHistoryIndexKey)};
        const auto execution_stage_progress{stages::read_stage_progress(txn, stages::kExecutionKey)};
        if (previous_progress <= to || execution_stage_progress <= to) {
            // Nothing to process
            operation_ = OperationType::kNone;
            return ret;
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

        if (previous_progress_accounts && previous_progress_accounts > to)
            success_or_throw(unwind_impl(txn, previous_progress_accounts, to, false));
        if (previous_progress_storage && previous_progress_storage > to)
            success_or_throw(unwind_impl(txn, previous_progress_storage, to, true));

        reset_log_progress();
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

    collector_.reset();
    operation_ = OperationType::kNone;
    return is_stopping() ? Stage::Result::kAborted : ret;
}

Stage::Result HistoryIndex::prune(RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::kPrune;
    try {
        throw_if_stopping();
        if (!prune_mode_history_.enabled()) {
            operation_ = OperationType::kNone;
            return ret;
        }

        const auto forward_progress{get_progress(txn)};
        const auto prune_progress{get_prune_progress(txn)};
        if (prune_progress >= forward_progress) {
            operation_ = OperationType::kNone;
            return ret;
        }

        // Need to erase all history info below this threshold
        // If threshold is zero we don't have anything to prune
        const auto prune_threshold{prune_mode_history_.value_from_head(forward_progress)};
        if (!prune_threshold) {
            operation_ = OperationType::kNone;
            return ret;
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

        // We split the stage in two
        const auto prune_progress_accounts{
            stages::read_stage_prune_progress(txn, stages::kAccountHistoryIndexKey)};
        const auto prune_progress_storage{
            stages::read_stage_prune_progress(txn, stages::kStorageHistoryIndexKey)};

        if (!prune_progress_accounts || prune_progress_accounts < forward_progress)
            success_or_throw(prune_impl(txn, prune_threshold, forward_progress, /*storage=*/false));
        if (!prune_progress_storage || prune_progress_storage < forward_progress)
            success_or_throw(prune_impl(txn, prune_threshold, forward_progress, /*storage=*/true));

        reset_log_progress();
        stages::write_stage_prune_progress(txn, stage_name_, forward_progress);
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

    operation_ = OperationType::kNone;
    return ret;
}

Stage::Result HistoryIndex::forward_impl(RWTxn& txn, const BlockNum from, const BlockNum to, const bool storage) {
    const MapConfig source_config{storage ? table::kStorageChangeSet : table::kAccountChangeSet};
    const MapConfig target_config{storage ? table::kStorageHistory : table::kAccountHistory};
    const size_t target_key_size{kAddressLength + (storage ? kHashLength : 0)};

    std::unique_lock log_lck(sl_mutex_);
    loading_ = false;
    current_source_ = std::string(source_config.name);
    current_target_ = std::string(target_config.name);
    current_key_.clear();
    log_lck.unlock();

    // Into etl
    collect_bitmaps_from_changeset(txn, source_config, from, to, storage);

    if (!collector_->empty()) {
        log_lck.lock();
        loading_ = true;
        index_loader_ = std::make_unique<bitmap::IndexLoader>(target_config);
        log_lck.unlock();
        index_loader_->merge_bitmaps(txn, target_key_size, collector_.get());

        log_lck.lock();
        loading_ = false;
        index_loader_.reset();
        current_source_.clear();
        current_target_.clear();
        log_lck.unlock();
    }

    stages::write_stage_progress(
        txn, (storage ? stages::kStorageHistoryIndexKey : stages::kAccountHistoryIndexKey), to);

    return Stage::Result::kSuccess;
}

Stage::Result HistoryIndex::unwind_impl(RWTxn& txn, const BlockNum from, const BlockNum to, const bool storage) {
    const MapConfig source_config{storage ? table::kStorageChangeSet : table::kAccountChangeSet};
    const MapConfig target_config{storage ? table::kStorageHistory : table::kAccountHistory};

    std::unique_lock log_lck(sl_mutex_);
    loading_ = false;
    current_source_ = std::string(source_config.name);
    current_target_ = std::string(target_config.name);
    current_key_.clear();
    log_lck.unlock();

    const auto keys{collect_unique_keys_from_changeset(txn, source_config, from, to, storage)};

    log_lck.lock();
    index_loader_ = std::make_unique<bitmap::IndexLoader>(target_config);
    log_lck.unlock();

    index_loader_->unwind_bitmaps(txn, to, keys);

    log_lck.lock();
    index_loader_.reset();
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();

    stages::write_stage_progress(
        txn, (storage ? stages::kStorageHistoryIndexKey : stages::kAccountHistoryIndexKey), to);

    return Stage::Result::kSuccess;
}

Stage::Result HistoryIndex::prune_impl(RWTxn& txn, const BlockNum threshold, const BlockNum to, const bool storage) {
    const MapConfig table_config{storage ? table::kStorageHistory : table::kAccountHistory};

    std::unique_lock log_lck(sl_mutex_);
    loading_ = false;
    current_source_ = std::string(table_config.name);
    current_target_ = current_source_;
    current_key_.clear();
    index_loader_ = std::make_unique<bitmap::IndexLoader>(table_config);
    log_lck.unlock();

    index_loader_->prune_bitmaps(txn, threshold);

    log_lck.lock();
    index_loader_.reset();
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();

    stages::write_stage_prune_progress(
        txn, (storage ? stages::kStorageHistoryIndexKey : stages::kAccountHistoryIndexKey), to);

    return Stage::Result::kSuccess;
}

void HistoryIndex::collect_bitmaps_from_changeset(RWTxn& txn, const MapConfig& source_config,
                                                  const BlockNum from, const BlockNum to, bool storage) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    absl::btree_map<Bytes, roaring::Roaring64Map> bitmaps;
    auto bitmaps_it{bitmaps.begin()};
    Bytes bitmaps_key{};
    size_t bitmaps_size{0};   // To account flushing threshold
    uint16_t flush_count{0};  // To account number of flushings

    const BlockNum max_block_num{to};
    BlockNum reached_block_num{0};

    auto start_key{block_key(from + 1)};
    auto source = txn.ro_cursor_dup_sort(source_config);
    auto source_data{storage ? source->lower_bound(to_slice(start_key), false)
                             : source->find(to_slice(start_key), false)};
    while (source_data) {
        auto source_data_key_view{from_slice(source_data.key)};
        reached_block_num = endian::load_big_u64(source_data_key_view.data());
        if (reached_block_num > max_block_num) {
            break;
        }
        source_data_key_view.remove_prefix(sizeof(BlockNum));

        // Log and abort check
        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            std::unique_lock log_lck(sl_mutex_);
            current_key_ = std::to_string(reached_block_num);
            log_time = now + 5s;
        }

        while (source_data) {
            const auto source_data_value_view{from_slice(source_data.value)};
            if (storage) {
                // Contract address + location
                bitmaps_key.assign(source_data_key_view.substr(0, kAddressLength))
                    .append(source_data_value_view.substr(0, kHashLength));
            } else {
                // Only address for accounts
                bitmaps_key.assign(source_data_value_view.substr(0, kAddressLength));
            }

            bitmaps_it = bitmaps.find(bitmaps_key);
            if (bitmaps_it == bitmaps.end()) {
                bitmaps_it = bitmaps.emplace(bitmaps_key, roaring::Roaring64Map()).first;
                bitmaps_size += bitmaps_key.size();
                bitmaps_size += sizeof(uint64_t);  // see Roaring64Map()::getSizeInBytes()
            }
            bitmaps_it->second.add(reached_block_num);
            bitmaps_size += sizeof(uint32_t);  // All blocks <= UINT32_MAX
                                               // Is there a chain exceeding that block_num ?

            source_data = source->to_current_next_multi(false);
        }

        // Flush bitmaps to etl if necessary
        if (bitmaps_size >= batch_size_) {
            bitmap::IndexLoader::flush_bitmaps_to_etl(bitmaps, collector_.get(), flush_count++);
            bitmaps_size = 0;
        }

        source_data = source->to_next(false);
    }

    if (bitmaps_size) {
        bitmap::IndexLoader::flush_bitmaps_to_etl(bitmaps, collector_.get(), flush_count);
    }
}

std::map<Bytes, bool> HistoryIndex::collect_unique_keys_from_changeset(
    RWTxn& txn, const MapConfig& source_config, BlockNum from, BlockNum to, bool storage) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    std::map<Bytes, bool> ret;
    Bytes unique_key{};

    const BlockNum max_block_num{std::max(from, to)};

    auto start_key{block_key(std::min(from, to) + 1)};
    auto source = txn.ro_cursor_dup_sort(source_config);
    auto source_data{storage ? source->lower_bound(to_slice(start_key), false)
                             : source->find(to_slice(start_key), false)};

    BlockNum reached_block_num{0};
    while (source_data) {
        auto source_data_key_view{from_slice(source_data.key)};
        reached_block_num = endian::load_big_u64(source_data_key_view.data());
        if (reached_block_num > max_block_num) break;
        source_data_key_view.remove_prefix(sizeof(BlockNum));

        // Log and abort check
        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            std::unique_lock log_lck(sl_mutex_);
            current_key_ = std::to_string(reached_block_num);
            log_time = now + 5s;
        }

        while (source_data) {
            auto source_data_value_view{from_slice(source_data.value)};
            if (storage) {
                // Contract address + location
                unique_key.assign(source_data_key_view.substr(0, kAddressLength))
                    .append(source_data_value_view.substr(0, kHashLength));
                source_data_value_view.remove_prefix(kHashLength);
            } else {
                // Only address for accounts
                unique_key.assign(source_data_value_view.substr(0, kAddressLength));
                source_data_value_view.remove_prefix(kAddressLength);
            }
            if (!ret.contains(unique_key)) {
                (void)ret.emplace(unique_key, source_data_value_view.empty());
            }
            source_data = source->to_current_next_multi(false);
        }

        source_data = source->to_next(false);
    }

    return ret;
}

std::vector<std::string> HistoryIndex::get_log_progress() {
    std::unique_lock log_lck(sl_mutex_);
    std::vector<std::string> ret{"op", std::string(magic_enum::enum_name<OperationType>(operation_))};
    if (current_source_.empty() && current_target_.empty()) {
        ret.insert(ret.end(), {"db", "waiting ..."});
    } else {
        switch (operation_) {
            case OperationType::kForward:
                if (loading_) {
                    current_key_ = collector_ ? abridge(collector_->get_load_key(), kAddressLength) : "";
                    ret.insert(ret.end(), {"from", "etl", "to", current_target_, "key", current_key_});
                } else {
                    ret.insert(ret.end(), {"from", current_source_, "to", "etl", "key", current_key_});
                }
                break;
            case OperationType::kUnwind:
                if (index_loader_) {
                    current_key_ = index_loader_->get_current_key();
                    ret.insert(ret.end(), {"from", "etl", "to", current_target_, "key", current_key_});
                } else {
                    ret.insert(ret.end(), {"from", current_source_, "to", "etl", "key", current_key_});
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

void HistoryIndex::reset_log_progress() {
    std::unique_lock log_lck(sl_mutex_);
    loading_ = false;
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
}
}  // namespace silkworm::stagedsync
