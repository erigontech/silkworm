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

#include "stage_senders.hpp"

#include <silkworm/common/stopwatch.hpp>

namespace silkworm::stagedsync {

StageResult Senders::forward(db::RWTxn& txn) {
    if (!node_settings_->chain_config.has_value()) {
        return StageResult::kUnknownChainId;
    }

    farm_ = std::make_unique<recovery::RecoveryFarm>(txn, node_settings_, log_prefix_);
    const auto res{farm_->recover()};
    if (res == StageResult::kSuccess) {
        txn.commit();
    }
    farm_.reset();
    return res;
}

StageResult Senders::unwind(db::RWTxn& txn) {
    StageResult ret{StageResult::kSuccess};

    if (!sync_context_->unwind_to.has_value()) return ret;
    const BlockNum to{sync_context_->unwind_to.value()};

    operation_ = OperationType::Unwind;
    current_key_.clear();

    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};
    std::unique_ptr<StopWatch> sw;
    if (log::test_verbosity(log::Level::kTrace)) {
        sw = std::make_unique<StopWatch>(/*auto_start=*/true);
    }

    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        const auto bodies_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kBlockBodiesKey)};
        if (previous_progress <= to || bodies_stage_progress <= to) {
            // Nothing to process
            operation_ = OperationType::None;
            return ret;
        }

        const BlockNum segment_width{previous_progress - to};
        if (segment_width > db::stages::kSmallSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(previous_progress),
                       "to", std::to_string(to),
                       "span", std::to_string(segment_width)});
        }

        db::Cursor unwind_table(txn, db::table::kSenders);
        const auto start_key{db::block_key(to + 1)};
        size_t erased{0};
        auto data{unwind_table.lower_bound(db::to_slice(start_key), /*throw_notfound=*/false)};
        while (data) {
            // Log and abort check
            if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
                throw_if_stopping();
                std::unique_lock log_lck(sl_mutex_);
                const auto reached_block_number{endian::load_big_u64(db::from_slice(data.key).data())};
                current_key_ = std::to_string(reached_block_number);
                log_time = now + 5s;
            }
            unwind_table.erase();
            ++erased;
            data = unwind_table.to_next(/*throw_notfound=*/false);
        }
        if (sw) {
            const auto [_, duration]{sw->lap()};
            log::Trace(log_prefix_,
                       {"origin", db::table::kSenders.name,
                        "erased", std::to_string(erased),
                        "in", StopWatch::format(duration)});
        }

        update_progress(txn, to);
        txn.commit();

    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<StageResult>(ex.err());
    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = StageResult::kDbError;
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = StageResult::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        ret = StageResult::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return ret;
}

StageResult Senders::prune(db::RWTxn& txn) {
    StageResult ret{StageResult::kSuccess};
    operation_ = OperationType::Prune;
    current_key_.clear();
    std::unique_ptr<StopWatch> sw;
    if (log::test_verbosity(log::Level::kTrace)) {
        sw = std::make_unique<StopWatch>(/*auto_start=*/true);
    }

    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    try {
        throw_if_stopping();
        if (!node_settings_->prune_mode->senders().enabled()) {
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
        const auto prune_threshold{node_settings_->prune_mode->senders().value_from_head(forward_progress)};
        if (!prune_threshold) {
            operation_ = OperationType::None;
            return ret;
        }

        const BlockNum segment_width{forward_progress - prune_progress};
        if (segment_width > db::stages::kSmallSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(prune_progress),
                       "to", std::to_string(forward_progress),
                       "threshold", std::to_string(prune_threshold)});
        }

        db::Cursor prune_table(txn, db::table::kSenders);
        const auto upper_key{db::block_key(prune_threshold)};
        size_t erased{0};
        if (prune_table.lower_bound(db::to_slice(upper_key))) {
            auto prune_data{prune_table.to_previous(/*throw_notfound=*/false)};
            while (prune_data) {
                // Log and abort check
                if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
                    throw_if_stopping();
                    std::unique_lock log_lck(sl_mutex_);
                    const auto reached_block_number{endian::load_big_u64(db::from_slice(prune_data.key).data())};
                    current_key_ = std::to_string(reached_block_number);
                    log_time = now + 5s;
                }

                prune_table.erase();
                ++erased;
                prune_data = prune_table.to_previous(/*throw_notfound=*/false);
            }
        }

        throw_if_stopping();
        if (sw) {
            const auto [_, duration]{sw->lap()};
            log::Trace(log_prefix_, {"source", db::table::kSenders.name, "erased", std::to_string(erased), "in", StopWatch::format(duration)});
        }
        db::stages::write_stage_prune_progress(txn, stage_name_, forward_progress);
        txn.commit();

    } catch (const StageError& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = static_cast<StageResult>(ex.err());
    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = StageResult::kDbError;
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        ret = StageResult::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        ret = StageResult::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return ret;
}

bool Senders::stop() {
    if (farm_) {
        (void)farm_->stop();
    }
    return IStage::stop();
}

std::vector<std::string> Senders::get_log_progress() {
    switch (operation_) {
        case OperationType::Forward:
            if (farm_) return farm_->get_log_progress();
        default:
            return {"key", current_key_};
    }
}

}  // namespace silkworm::stagedsync
