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

#include "stage_log_index.hpp"

namespace silkworm::stagedsync {

Stage::Result LogIndex::forward(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::Forward;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        auto previous_progress{get_progress(txn)};
        const auto target_progress{db::stages::read_stage_progress(*txn, db::stages::kExecutionKey)};
        if (previous_progress == target_progress) {
            // Nothing to process
            operation_ = OperationType::None;
            return ret;
        } else if (previous_progress > target_progress) {
            // Something bad had happened.  Maybe we need to unwind ?
            throw StageError(Stage::Result::kInvalidProgress,
                             "LogIndex progress " + std::to_string(previous_progress) +
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
            if (!previous_progress)
                previous_progress = node_settings_->prune_mode->history().value_from_head(target_progress);
        }

        if (previous_progress < target_progress)
            forward_impl(txn, previous_progress, target_progress);

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

    operation_ = OperationType::None;
    addresses_collector_.reset();
    topics_collector_.reset();
    return ret;
}

Stage::Result LogIndex::unwind(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};

    if (!sync_context_->unwind_point.has_value()) return ret;
    const BlockNum to{sync_context_->unwind_point.value()};

    operation_ = OperationType::Unwind;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
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

        if (previous_progress && previous_progress > to)
            unwind_impl(txn, previous_progress, to);

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

    addresses_collector_.reset();
    topics_collector_.reset();
    operation_ = OperationType::None;
    return ret;
}

Stage::Result LogIndex::prune(db::RWTxn& txn) {
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

        if (!prune_progress || prune_progress < forward_progress) {
            prune_impl(txn, prune_threshold, db::table::kLogAddressIndex);
            prune_impl(txn, prune_threshold, db::table::kLogTopicIndex);
        }

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

    addresses_collector_.reset();
    topics_collector_.reset();
    return ret;
}

void LogIndex::forward_impl(db::RWTxn& txn, const BlockNum from, const BlockNum to) {
    const db::MapConfig source_config{db::table::kLogs};

    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::Forward;
    loading_ = false;
    topics_collector_ = std::make_unique<etl::Collector>(node_settings_);
    addresses_collector_ = std::make_unique<etl::Collector>(node_settings_);
    current_source_ = std::string(source_config.name);
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();

    // Into etl collectors
    collect_bitmaps_from_logs(txn, source_config, from, to);

    log_lck.lock();
    loading_ = true;
    current_key_.clear();
    current_target_ = db::table::kLogAddressIndex.name;
    index_loader_ = std::make_unique<db::bitmap::IndexLoader>(db::table::kLogAddressIndex);
    log_lck.unlock();

    index_loader_->merge_bitmaps(txn, kAddressLength, addresses_collector_.get());

    log_lck.lock();
    current_key_.clear();
    current_target_ = db::table::kLogTopicIndex.name;
    index_loader_ = std::make_unique<db::bitmap::IndexLoader>(db::table::kLogTopicIndex);
    log_lck.unlock();

    index_loader_->merge_bitmaps(txn, kHashLength, topics_collector_.get());

    log_lck.lock();
    loading_ = false;
    current_target_.clear();
    index_loader_.reset();
    log_lck.unlock();
}

void LogIndex::unwind_impl(db::RWTxn& txn, BlockNum from, BlockNum to) {
    const db::MapConfig source_config{db::table::kLogs};

    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::Unwind;
    loading_ = false;
    current_source_ = std::string(source_config.name);
    current_key_.clear();
    log_lck.unlock();

    std::map<Bytes, bool> addresses_keys;
    std::map<Bytes, bool> topics_keys;
    collect_unique_keys_from_logs(txn, source_config, from, to, addresses_keys, topics_keys);

    log_lck.lock();
    current_target_ = db::table::kLogAddressIndex.name;
    index_loader_ = std::make_unique<db::bitmap::IndexLoader>(db::table::kLogAddressIndex);
    log_lck.unlock();

    index_loader_->unwind_bitmaps(txn, to, addresses_keys);

    log_lck.lock();
    current_target_ = db::table::kLogTopicIndex.name;
    index_loader_ = std::make_unique<db::bitmap::IndexLoader>(db::table::kLogTopicIndex);
    log_lck.unlock();

    index_loader_->unwind_bitmaps(txn, to, topics_keys);

    log_lck.lock();
    index_loader_.reset();
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();
}

void LogIndex::collect_bitmaps_from_logs(db::RWTxn& txn,
                                         const db::MapConfig& source_config,
                                         BlockNum from, BlockNum to) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    const BlockNum max_block_number{to};
    BlockNum reached_block_number{0};

    absl::btree_map<Bytes, roaring::Roaring64Map> topics_bitmaps;
    absl::btree_map<Bytes, roaring::Roaring64Map> addresses_bitmaps;
    size_t topics_bitmaps_size{0};
    size_t addresses_bitmaps_size{0};
    uint16_t topics_flush_count{0};
    uint16_t addresses_flush_count{0};

    // The function we use to collect decoded data into bitmaps
    cbor_function on_log_bytes{[&topics_bitmaps,
                                &topics_bitmaps_size,
                                &addresses_bitmaps,
                                &addresses_bitmaps_size,
                                &reached_block_number](unsigned char* data, int size) -> void {
        // We need either a hash or an address
        auto s{static_cast<size_t>(size)};
        if (s != kHashLength && s != kAddressLength) return;

        Bytes key(data, s);
        if (key.size() == kHashLength) {
            auto it{topics_bitmaps.find(key)};
            if (it == topics_bitmaps.end()) {
                it = topics_bitmaps.emplace(key, roaring::Roaring64Map()).first;
                topics_bitmaps_size += key.size() + sizeof(BlockNum);
            }
            it->second.add(reached_block_number);
            topics_bitmaps_size += sizeof(uint32_t);
        } else {
            auto it{addresses_bitmaps.find(key)};
            if (it == addresses_bitmaps.end()) {
                it = addresses_bitmaps.emplace(key, roaring::Roaring64Map()).first;
                addresses_bitmaps_size += key.size() + sizeof(BlockNum);
            }
            it->second.add(reached_block_number);
            addresses_bitmaps_size += sizeof(uint32_t);
        }
    }};

    // Listener to CBOR decoder
    CborListener listener{on_log_bytes};

    auto start_key{db::block_key(from + 1)};
    db::Cursor source(txn, source_config);
    auto source_data{source.lower_bound(db::to_slice(start_key), false)};
    while (source_data) {
        reached_block_number = endian::load_big_u64(static_cast<uint8_t*>(source_data.key.data()));
        if (reached_block_number > max_block_number) break;

        // Log and abort check
        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            std::unique_lock log_lck(sl_mutex_);
            current_key_ = std::to_string(reached_block_number);
            log_time = now + 5s;
        }

        // Decode CBOR value content and distribute it to the 2 bitmaps
        cbor::input input(source_data.value.data(), static_cast<int>(source_data.value.length()));
        cbor::decoder decoder(input, listener);
        decoder.run();

        // Flushes
        if (topics_bitmaps_size > node_settings_->batch_size) {
            db::bitmap::IndexLoader::flush_bitmaps_to_etl(topics_bitmaps,
                                                          topics_collector_.get(),
                                                          topics_flush_count++);
            topics_bitmaps_size = 0;
        }

        if (addresses_bitmaps_size > node_settings_->batch_size) {
            db::bitmap::IndexLoader::flush_bitmaps_to_etl(addresses_bitmaps,
                                                          addresses_collector_.get(),
                                                          addresses_flush_count++);
            addresses_bitmaps_size = 0;
        }

        source_data = source.to_next(/*throw_notfound=*/false);
    }
}

void LogIndex::collect_unique_keys_from_logs(db::RWTxn& txn,
                                             const db::MapConfig& source_config,
                                             BlockNum from, BlockNum to,
                                             std::map<Bytes, bool>& addresses,
                                             std::map<Bytes, bool>& topics) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    BlockNum expected_block_number{std::min(from, to) + 1};
    const BlockNum max_block_number{std::max(from, to)};
    BlockNum reached_block_number{0};

    // The function we use to collect decoded data into bitmaps
    cbor_function on_log_bytes{[&addresses,
                                &topics](unsigned char* data, int size) -> void {
        // We need either a hash or an address
        auto s{static_cast<size_t>(size)};
        if (s != kHashLength && s != kAddressLength) return;

        Bytes key(data, s);
        if (key.size() == kHashLength) {
            (void)topics.try_emplace(key, false);
        } else {
            (void)addresses.try_emplace(key, false);
        }
    }};

    // Listener to CBOR decoder
    CborListener listener{on_log_bytes};

    auto start_key{db::block_key(expected_block_number)};
    db::Cursor source(txn, source_config);
    auto source_data{source.lower_bound(db::to_slice(start_key), false)};
    while (source_data) {
        reached_block_number = endian::load_big_u64(static_cast<uint8_t*>(source_data.key.data()));
        if (reached_block_number > max_block_number) break;

        // Log and abort check
        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            std::unique_lock log_lck(sl_mutex_);
            current_key_ = std::to_string(reached_block_number);
            log_time = now + 5s;
        }

        // Decode CBOR value content and distribute it to the 2 bitmaps
        cbor::input input(source_data.value.data(), static_cast<int>(source_data.value.length()));
        cbor::decoder decoder(input, listener);
        decoder.run();
        source_data = source.to_next(/*throw_notfound=*/false);
    }
}

void LogIndex::prune_impl(db::RWTxn& txn, BlockNum threshold, const db::MapConfig& target) {
    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::Prune;
    loading_ = false;
    current_source_ = target.name;
    current_target_ = current_source_;
    current_key_.clear();
    index_loader_ = std::make_unique<db::bitmap::IndexLoader>(target);
    log_lck.unlock();

    index_loader_->prune_bitmaps(txn, threshold);

    log_lck.lock();
    index_loader_.reset();
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();
}

std::vector<std::string> LogIndex::get_log_progress() {
    std::vector<std::string> ret{"op", std::string(magic_enum::enum_name<OperationType>(operation_))};
    std::unique_lock log_lck(sl_mutex_);
    if (current_source_.empty() && current_target_.empty()) {
        ret.insert(ret.end(), {"db", "waiting ..."});
    } else {
        switch (operation_) {
            case OperationType::Forward:
                if (loading_) {
                    if (current_target_ == db::table::kLogAddressIndex.name) {
                        current_key_ = abridge(addresses_collector_->get_load_key(), kAddressLength);
                    } else if (current_target_ == db::table::kLogTopicIndex.name) {
                        current_key_ = abridge(topics_collector_->get_load_key(), kAddressLength);
                    } else {
                        current_key_.clear();
                    }
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
void LogIndex::reset_log_progress() {
    std::unique_lock log_lck(sl_mutex_);
    loading_ = false;
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
}
}  // namespace silkworm::stagedsync
