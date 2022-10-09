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

#include "stage_history_index.hpp"

#include <silkworm/common/cast.hpp>
#include <silkworm/common/endian.hpp>

namespace silkworm::stagedsync {

Stage::Result HistoryIndex::forward(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::Forward;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        auto previous_progress_accounts{db::stages::read_stage_progress(*txn, db::stages::kAccountHistoryIndexKey)};
        auto previous_progress_storage{db::stages::read_stage_progress(*txn, db::stages::kStorageHistoryIndexKey)};
        const auto target_progress{db::stages::read_stage_progress(*txn, db::stages::kExecutionKey)};
        if (previous_progress == target_progress) {
            // Nothing to process
            operation_ = OperationType::None;
            return ret;
        } else if (previous_progress > target_progress) {
            // Something bad had happened.  Maybe we need to unwind ?
            throw StageError(Stage::Result::kInvalidProgress,
                             "HistoryIndex progress " + std::to_string(previous_progress) +
                                 " greater than Execution progress " + std::to_string(target_progress));
        }

        reset_log_progress();
        const BlockNum segment_width{target_progress - previous_progress};
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(previous_progress),
                       "to", std::to_string(target_progress),
                       "span", std::to_string(segment_width)});
        }

        // If this is first time we forward AND we have "prune history" set
        // do not process all blocks rather only what is needed
        if (node_settings_->prune_mode->history().enabled()) {
            if (!previous_progress_accounts)
                previous_progress_accounts = node_settings_->prune_mode->history().value_from_head(target_progress);
            if (!previous_progress_storage)
                previous_progress_storage = node_settings_->prune_mode->history().value_from_head(target_progress);
        }

        collector_ = std::make_unique<etl::Collector>(node_settings_);
        if (previous_progress_accounts < target_progress) {
            success_or_throw(forward_impl(txn, previous_progress_accounts, target_progress, false));
            txn.commit();
        }
        if (previous_progress_storage < target_progress) {
            success_or_throw(forward_impl(txn, previous_progress_storage, target_progress, true));
            txn.commit();
        }
        reset_log_progress();
        update_progress(txn, target_progress);
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
                   {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    collector_.reset();
    operation_ = OperationType::None;
    return is_stopping() ? Stage::Result::kAborted : ret;
}

Stage::Result HistoryIndex::unwind(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};

    if (!sync_context_->unwind_point.has_value()) return ret;
    const BlockNum to{sync_context_->unwind_point.value()};

    operation_ = OperationType::None;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        const auto previous_progress_accounts{
            db::stages::read_stage_progress(*txn, db::stages::kAccountHistoryIndexKey)};
        const auto previous_progress_storage{
            db::stages::read_stage_progress(*txn, db::stages::kStorageHistoryIndexKey)};
        const auto execution_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kExecutionKey)};
        if (previous_progress <= to || execution_stage_progress <= to) {
            // Nothing to process
            operation_ = OperationType::None;
            return ret;
        }

        reset_log_progress();
        const BlockNum segment_width{previous_progress - to};
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
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
                   {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    collector_.reset();
    operation_ = OperationType::None;
    return is_stopping() ? Stage::Result::kAborted : ret;
}

Stage::Result HistoryIndex::prune(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::Prune;
    try {
        throw_if_stopping();
        if (!node_settings_->prune_mode->history().enabled()) {
            operation_ = OperationType::None;
            return ret;
        }

        const auto forward_progress{get_progress(txn)};
        const auto prune_progress{get_prune_progress(txn)};
        if (prune_progress >= forward_progress) {
            operation_ = OperationType::None;
            return ret;
        }

        // Need to erase all history info below this threshold
        // If threshold is zero we don't have anything to prune
        const auto prune_threshold{node_settings_->prune_mode->history().value_from_head(forward_progress)};
        if (!prune_threshold) {
            operation_ = OperationType::None;
            return ret;
        }

        reset_log_progress();
        const BlockNum segment_width{forward_progress - prune_progress};
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(prune_progress),
                       "to", std::to_string(forward_progress),
                       "threshold", std::to_string(prune_threshold)});
        }

        // We split the stage in two
        const auto prune_progress_accounts{
            db::stages::read_stage_prune_progress(*txn, db::stages::kAccountHistoryIndexKey)};
        const auto prune_progress_storage{
            db::stages::read_stage_prune_progress(*txn, db::stages::kStorageHistoryIndexKey)};

        if (!prune_progress_accounts || prune_progress_accounts < forward_progress)
            success_or_throw(prune_impl(txn, prune_threshold, forward_progress, /*storage=*/false));
        if (!prune_progress_storage || prune_progress_storage < forward_progress)
            success_or_throw(prune_impl(txn, prune_threshold, forward_progress, /*storage=*/true));

        reset_log_progress();
        db::stages::write_stage_prune_progress(*txn, stage_name_, forward_progress);
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
                   {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        ret = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return ret;
}

Stage::Result HistoryIndex::forward_impl(db::RWTxn& txn, const BlockNum from, const BlockNum to, const bool storage) {
    const db::MapConfig source_config{storage ? db::table::kStorageChangeSet : db::table::kAccountChangeSet};
    const db::MapConfig target_config{storage ? db::table::kStorageHistory : db::table::kAccountHistory};
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
        index_loader_ = std::make_unique<db::bitmap::IndexLoader>(target_config);
        log_lck.unlock();
        index_loader_->merge_bitmaps(txn, target_key_size, collector_.get());

        log_lck.lock();
        loading_ = false;
        index_loader_.reset();
        current_source_.clear();
        current_target_.clear();
        log_lck.unlock();
    }

    db::stages::write_stage_progress(
        *txn, (storage ? db::stages::kStorageHistoryIndexKey : db::stages::kAccountHistoryIndexKey), to);

    return Stage::Result::kSuccess;
}

Stage::Result HistoryIndex::unwind_impl(db::RWTxn& txn, const BlockNum from, const BlockNum to, const bool storage) {
    const db::MapConfig source_config{storage ? db::table::kStorageChangeSet : db::table::kAccountChangeSet};
    const db::MapConfig target_config{storage ? db::table::kStorageHistory : db::table::kAccountHistory};

    std::unique_lock log_lck(sl_mutex_);
    loading_ = false;
    current_source_ = std::string(source_config.name);
    current_target_ = std::string(target_config.name);
    current_key_.clear();
    log_lck.unlock();

    const auto keys{collect_unique_keys_from_changeset(txn, source_config, from, to, storage)};

    log_lck.lock();
    index_loader_ = std::make_unique<db::bitmap::IndexLoader>(target_config);
    log_lck.unlock();

    index_loader_->unwind_bitmaps(txn, to, keys);

    log_lck.lock();
    index_loader_.reset();
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();

    db::stages::write_stage_progress(
        *txn, (storage ? db::stages::kStorageHistoryIndexKey : db::stages::kAccountHistoryIndexKey), to);

    return Stage::Result::kSuccess;
}

Stage::Result HistoryIndex::prune_impl(db::RWTxn& txn, const BlockNum threshold, const BlockNum to, const bool storage) {
    const db::MapConfig table_config{storage ? db::table::kStorageHistory : db::table::kAccountHistory};

    std::unique_lock log_lck(sl_mutex_);
    loading_ = false;
    current_source_ = std::string(table_config.name);
    current_target_ = current_source_;
    current_key_.clear();
    index_loader_ = std::make_unique<db::bitmap::IndexLoader>(table_config);
    log_lck.unlock();

    index_loader_->prune_bitmaps(txn, threshold);

    log_lck.lock();
    index_loader_.reset();
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();

    db::stages::write_stage_prune_progress(
        *txn, (storage ? db::stages::kStorageHistoryIndexKey : db::stages::kAccountHistoryIndexKey), to);

    return Stage::Result::kSuccess;
}

void HistoryIndex::collect_bitmaps_from_changeset(db::RWTxn& txn, const db::MapConfig& source_config,
                                                  const BlockNum from, const BlockNum to, bool storage) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    absl::btree_map<Bytes, roaring::Roaring64Map> bitmaps;
    auto bitmaps_it{bitmaps.begin()};
    Bytes bitmaps_key{};
    size_t bitmaps_size{0};   // To account flushing threshold
    uint16_t flush_count{0};  // To account number of flushings

    const BlockNum max_block_number{to};
    BlockNum reached_block_number{0};

    auto start_key{db::block_key(from + 1)};
    db::Cursor source(txn, source_config);
    auto source_data{storage ? source.lower_bound(db::to_slice(start_key), false)
                             : source.find(db::to_slice(start_key), false)};
    while (source_data) {
        auto source_data_key_view{db::from_slice(source_data.key)};
        reached_block_number = endian::load_big_u64(source_data_key_view.data());
        if (reached_block_number > max_block_number) {
            break;
        }
        source_data_key_view.remove_prefix(sizeof(BlockNum));

        // Log and abort check
        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            std::unique_lock log_lck(sl_mutex_);
            current_key_ = std::to_string(reached_block_number);
            log_time = now + 5s;
        }

        while (source_data) {
            const auto source_data_value_view{db::from_slice(source_data.value)};
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
            bitmaps_it->second.add(reached_block_number);
            bitmaps_size += sizeof(uint32_t);  // All blocks <= UINT32_MAX
                                               // Is there a chain exceeding that height ?

            source_data = source.to_current_next_multi(false);
        }

        // Flush bitmaps to etl if necessary
        if (bitmaps_size >= node_settings_->batch_size) {
            db::bitmap::IndexLoader::flush_bitmaps_to_etl(bitmaps, collector_.get(), flush_count++);
            bitmaps_size = 0;
        }

        source_data = source.to_next(false);
    }

    if (bitmaps_size) {
        db::bitmap::IndexLoader::flush_bitmaps_to_etl(bitmaps, collector_.get(), flush_count++);
        bitmaps_size = 0;
    }
}

std::map<Bytes, bool> HistoryIndex::collect_unique_keys_from_changeset(
    db::RWTxn& txn, const db::MapConfig& source_config, BlockNum from, BlockNum to, bool storage) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    std::map<Bytes, bool> ret;
    Bytes unique_key{};

    BlockNum expected_block_number{std::min(from, to) + 1};
    const BlockNum max_block_number{std::max(from, to)};
    BlockNum reached_block_number{0};

    auto start_key{db::block_key(expected_block_number)};
    db::Cursor source(txn, source_config);
    auto source_data{storage ? source.lower_bound(db::to_slice(start_key), false)
                             : source.find(db::to_slice(start_key), false)};

    while (source_data) {
        auto source_data_key_view{db::from_slice(source_data.key)};
        reached_block_number = endian::load_big_u64(source_data_key_view.data());
        check_block_sequence(expected_block_number, reached_block_number);
        if (reached_block_number > max_block_number) break;
        source_data_key_view.remove_prefix(sizeof(BlockNum));

        // Log and abort check
        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            std::unique_lock log_lck(sl_mutex_);
            current_key_ = std::to_string(reached_block_number);
            log_time = now + 5s;
        }

        while (source_data) {
            auto source_data_value_view{db::from_slice(source_data.value)};
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
            source_data = source.to_current_next_multi(false);
        }

        ++expected_block_number;
        source_data = source.to_next(false);
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
            case OperationType::Forward:
                if (loading_) {
                    current_key_ = collector_ ? abridge(collector_->get_load_key(), kAddressLength) : "";
                    ret.insert(ret.end(), {"from", "etl", "to", current_target_, "key", current_key_});
                } else {
                    ret.insert(ret.end(), {"from", current_source_, "to", "etl", "key", current_key_});
                }
                break;
            case OperationType::Unwind:
                if (index_loader_) {
                    current_key_ = index_loader_->get_current_key();
                    ret.insert(ret.end(), {"from", "etl", "to", current_target_, "key", current_key_});
                } else {
                    ret.insert(ret.end(), {"from", current_source_, "to", "etl", "key", current_key_});
                }
                break;
            case OperationType::Prune:
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
