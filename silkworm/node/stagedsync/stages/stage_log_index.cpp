// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stage_log_index.hpp"

#include <utility>

#include <gsl/narrow>
#include <magic_enum.hpp>

#include <silkworm/db/log_cbor.hpp>

namespace silkworm::stagedsync {

using namespace silkworm::db;
using silkworm::datastore::kvdb::to_slice;
namespace bitmap {
    using namespace silkworm::datastore::kvdb::bitmap;
}

namespace {
    //! LogBitmapBuilder is a CBOR consumer which builds address and topic roaring bitmaps from the CBOR
    //! representation of a sequence of Logs
    class LogBitmapBuilder : public LogCborConsumer {
      public:
        using AddressHandler = std::function<void(std::span<const uint8_t, kAddressLength>)>;
        using TopicHandler = std::function<void(HashAsSpan)>;

        LogBitmapBuilder(AddressHandler address_callback, TopicHandler topic_callback)
            : address_callback_{std::move(address_callback)}, topic_callback_{std::move(topic_callback)} {}

        void on_num_logs(size_t /*num_logs*/) override {}

        void on_address(std::span<const uint8_t, kAddressLength> address) override {
            address_callback_(address);
        }

        void on_num_topics(size_t /*num_topics*/) override {}

        void on_topic(HashAsSpan topic) override {
            topic_callback_(topic);
        }

        void on_data(std::span<const uint8_t> /*data*/) override {}

      private:
        AddressHandler address_callback_;
        TopicHandler topic_callback_;
    };
}  // namespace

Stage::Result LogIndex::forward(RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::kForward;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        auto previous_progress{get_progress(txn)};
        const auto target_progress{stages::read_stage_progress(txn, stages::kExecutionKey)};
        if (previous_progress == target_progress) {
            // Nothing to process
            operation_ = OperationType::kNone;
            return ret;
        }
        if (previous_progress > target_progress) {
            // Something bad had happened.  Maybe we need to unwind ?
            throw StageError(Stage::Result::kInvalidProgress,
                             "LogIndex progress " + std::to_string(previous_progress) +
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
            if (!previous_progress)
                previous_progress = prune_mode_history_.value_from_head(target_progress);
        }

        if (previous_progress < target_progress)
            forward_impl(txn, previous_progress, target_progress);

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

    operation_ = OperationType::kNone;
    addresses_collector_.reset();
    topics_collector_.reset();
    return ret;
}

Stage::Result LogIndex::unwind(RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};

    if (!sync_context_->unwind_point.has_value()) return ret;
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

        if (previous_progress && previous_progress > to)
            unwind_impl(txn, previous_progress, to);

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

    addresses_collector_.reset();
    topics_collector_.reset();
    operation_ = OperationType::kNone;
    return ret;
}

Stage::Result LogIndex::prune(RWTxn& txn) {
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

        if (!prune_progress || prune_progress < forward_progress) {
            prune_impl(txn, prune_threshold, table::kLogAddressIndex);
            prune_impl(txn, prune_threshold, table::kLogTopicIndex);
        }

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

    addresses_collector_.reset();
    topics_collector_.reset();
    return ret;
}

void LogIndex::forward_impl(RWTxn& txn, const BlockNum from, const BlockNum to) {
    using datastore::kvdb::Collector;

    const MapConfig source_config{table::kLogs};

    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::kForward;
    loading_ = false;
    topics_collector_ = std::make_unique<Collector>(etl_settings_);
    addresses_collector_ = std::make_unique<Collector>(etl_settings_);
    current_source_ = std::string(source_config.name);
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();

    // Into etl collectors
    collect_bitmaps_from_logs(txn, source_config, from, to);

    log_lck.lock();
    loading_ = true;
    current_key_.clear();
    current_target_ = table::kLogAddressIndex.name;
    index_loader_ = std::make_unique<bitmap::IndexLoader>(table::kLogAddressIndex);
    log_lck.unlock();

    index_loader_->merge_bitmaps32(txn, kAddressLength, addresses_collector_.get());

    log_lck.lock();
    current_key_.clear();
    current_target_ = table::kLogTopicIndex.name;
    index_loader_ = std::make_unique<bitmap::IndexLoader>(table::kLogTopicIndex);
    log_lck.unlock();

    index_loader_->merge_bitmaps32(txn, kHashLength, topics_collector_.get());

    log_lck.lock();
    loading_ = false;
    current_target_.clear();
    index_loader_.reset();
    log_lck.unlock();
}

void LogIndex::unwind_impl(RWTxn& txn, BlockNum from, BlockNum to) {
    const MapConfig source_config{table::kLogs};

    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::kUnwind;
    loading_ = false;
    current_source_ = std::string(source_config.name);
    current_key_.clear();
    log_lck.unlock();

    std::map<Bytes, bool> addresses_keys;
    std::map<Bytes, bool> topics_keys;
    collect_unique_keys_from_logs(txn, source_config, from, to, addresses_keys, topics_keys);

    log_lck.lock();
    current_target_ = table::kLogAddressIndex.name;
    index_loader_ = std::make_unique<bitmap::IndexLoader>(table::kLogAddressIndex);
    log_lck.unlock();

    index_loader_->unwind_bitmaps32(txn, to, addresses_keys);

    log_lck.lock();
    current_target_ = table::kLogTopicIndex.name;
    index_loader_ = std::make_unique<bitmap::IndexLoader>(table::kLogTopicIndex);
    log_lck.unlock();

    index_loader_->unwind_bitmaps32(txn, to, topics_keys);

    log_lck.lock();
    index_loader_.reset();
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();
}

void LogIndex::collect_bitmaps_from_logs(RWTxn& txn,
                                         const MapConfig& source_config,
                                         BlockNum from, BlockNum to) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    const BlockNum max_block_num{to};
    BlockNum reached_block_num{0};

    absl::btree_map<Bytes, roaring::Roaring> topics_bitmaps;
    absl::btree_map<Bytes, roaring::Roaring> addresses_bitmaps;
    size_t topics_bitmaps_size{0};
    size_t addresses_bitmaps_size{0};
    uint16_t topics_flush_count{0};
    uint16_t addresses_flush_count{0};

    // The CBOR consumer we use to collect decoded data into bitmaps
    LogBitmapBuilder bitmap_builder{
        [&](std::span<const uint8_t, kAddressLength> address_data) {
            Bytes key(address_data.data(), address_data.size());
            auto it{addresses_bitmaps.find(key)};
            if (it == addresses_bitmaps.end()) {
                it = addresses_bitmaps.emplace(key, roaring::Roaring()).first;
                addresses_bitmaps_size += key.size() + sizeof(uint32_t);
            }
            it->second.add(gsl::narrow<uint32_t>(reached_block_num));
            addresses_bitmaps_size += sizeof(uint32_t);
        },
        [&](HashAsSpan topic_data) {
            Bytes key(topic_data.data(), topic_data.size());
            auto it{topics_bitmaps.find(key)};
            if (it == topics_bitmaps.end()) {
                it = topics_bitmaps.emplace(key, roaring::Roaring()).first;
                topics_bitmaps_size += key.size() + sizeof(uint32_t);
            }
            it->second.add(gsl::narrow<uint32_t>(reached_block_num));
            topics_bitmaps_size += sizeof(uint32_t);
        }};

    auto start_key{block_key(from + 1)};
    auto source = txn.ro_cursor(source_config);
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

        // Decode CBOR value content and distribute it to the 2 bitmaps
        cbor_decode({static_cast<uint8_t*>(source_data.value.data()), source_data.value.length()}, bitmap_builder);

        // Flush bitmaps batch by batch
        if (topics_bitmaps_size > batch_size_) {
            bitmap::IndexLoader::flush_bitmaps_to_etl(topics_bitmaps,
                                                      topics_collector_.get(),
                                                      topics_flush_count++);
            topics_bitmaps_size = 0;
        }

        if (addresses_bitmaps_size > batch_size_) {
            bitmap::IndexLoader::flush_bitmaps_to_etl(addresses_bitmaps,
                                                      addresses_collector_.get(),
                                                      addresses_flush_count++);
            addresses_bitmaps_size = 0;
        }

        source_data = source->to_next(/*throw_notfound=*/false);
    }

    // Flush remaining portion of bitmaps (if any)
    bitmap::IndexLoader::flush_bitmaps_to_etl(topics_bitmaps, topics_collector_.get(), topics_flush_count);
    bitmap::IndexLoader::flush_bitmaps_to_etl(addresses_bitmaps, addresses_collector_.get(), addresses_flush_count);
}

void LogIndex::collect_unique_keys_from_logs(RWTxn& txn,
                                             const MapConfig& source_config,
                                             BlockNum from, BlockNum to,
                                             std::map<Bytes, bool>& addresses,
                                             std::map<Bytes, bool>& topics) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    BlockNum expected_block_num{std::min(from, to) + 1};
    const BlockNum max_block_num{std::max(from, to)};
    BlockNum reached_block_num{0};

    // The CBOR consumer we use to collect decoded data into bitmaps
    LogBitmapBuilder bitmap_builder{
        [&](std::span<const uint8_t, kAddressLength> address_data) {
            Bytes key(address_data.data(), address_data.size());
            (void)addresses.try_emplace(key, false);
        },
        [&](HashAsSpan topic_data) {
            Bytes key(topic_data.data(), topic_data.size());
            (void)topics.try_emplace(key, false);
        }};

    auto start_key{block_key(expected_block_num)};
    auto source = txn.ro_cursor(source_config);
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

        // Decode CBOR value content and distribute it to the 2 bitmaps
        cbor_decode({static_cast<uint8_t*>(source_data.value.data()), source_data.value.length()}, bitmap_builder);

        source_data = source->to_next(/*throw_notfound=*/false);
    }
}

void LogIndex::prune_impl(RWTxn& txn, BlockNum threshold, const MapConfig& target) {
    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::kPrune;
    loading_ = false;
    current_source_ = target.name;
    current_target_ = current_source_;
    current_key_.clear();
    index_loader_ = std::make_unique<bitmap::IndexLoader>(target);
    log_lck.unlock();

    index_loader_->prune_bitmaps32(txn, threshold);

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
            case OperationType::kForward:
                if (loading_) {
                    if (current_target_ == table::kLogAddressIndex.name && addresses_collector_) {
                        current_key_ = abridge(addresses_collector_->get_load_key(), kAddressLength);
                    } else if (current_target_ == table::kLogTopicIndex.name && topics_collector_) {
                        current_key_ = abridge(topics_collector_->get_load_key(), kAddressLength);
                    } else {
                        current_key_.clear();
                    }
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

void LogIndex::reset_log_progress() {
    std::unique_lock log_lck(sl_mutex_);
    loading_ = false;
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
}

}  // namespace silkworm::stagedsync
