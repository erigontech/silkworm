// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stage_tx_lookup.hpp"

#include <algorithm>
#include <stdexcept>

#include <magic_enum.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/db/access_layer.hpp>

namespace silkworm::stagedsync {

using namespace silkworm::db;
using datastore::kvdb::Collector;

Stage::Result TxLookup::forward(RWTxn& txn) {
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
                             "TxLookup progress " + std::to_string(previous_progress) +
                                 " greater than Execution progress " + std::to_string(target_progress));
        }

        // Snapshots already have TxLookup index, so we must start after max frozen block here
        DataModel data_model = data_model_factory_(txn);
        const auto max_frozen_block_num{data_model.max_frozen_block_num()};
        if (max_frozen_block_num > previous_progress) {
            previous_progress = std::min(max_frozen_block_num, target_progress);
            // If pruning is enabled, make it start from max frozen block as well
            if (prune_mode_tx_index_.enabled()) {
                set_prune_progress(txn, previous_progress);
            }
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
        if (!previous_progress && prune_mode_tx_index_.enabled())
            previous_progress = prune_mode_tx_index_.value_from_head(target_progress);

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
    collector_.reset();
    return ret;
}

Stage::Result TxLookup::unwind(RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};

    if (!sync_context_->unwind_point.has_value()) return ret;
    BlockNum to{sync_context_->unwind_point.value()};

    operation_ = OperationType::kUnwind;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        const auto execution_progress{stages::read_stage_progress(txn, stages::kExecutionKey)};
        if (previous_progress <= to || execution_progress <= to) {
            // Nothing to process
            operation_ = OperationType::kNone;
            return ret;
        }

        // Snapshots already have TxLookup index, so we must stop before max frozen block here
        DataModel data_model = data_model_factory_(txn);
        const auto max_frozen_block_num{data_model.max_frozen_block_num()};
        to = std::max(to, max_frozen_block_num);

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

    operation_ = OperationType::kNone;
    collector_.reset();
    return ret;
}

Stage::Result TxLookup::prune(RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::kPrune;

    try {
        throw_if_stopping();
        if (!prune_mode_tx_index_.enabled()) {
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
        const auto prune_threshold{prune_mode_tx_index_.value_from_head(forward_progress)};
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
            const auto previous_prune_threshold = prune_mode_tx_index_.value_from_head(prune_progress);
            prune_impl(txn, previous_prune_threshold, prune_threshold);
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

    operation_ = OperationType::kNone;
    return ret;
}

void TxLookup::forward_impl(RWTxn& txn, const BlockNum from, const BlockNum to) {
    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::kForward;
    loading_.store(false);
    collector_ = std::make_unique<Collector>(etl_settings_);
    current_source_ = std::string(table::kBlockBodies.name);
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();

    // Into etl collector
    collect_transaction_hashes_from_canonical_bodies(txn, from, to, /*for_deletion=*/false);

    log_lck.lock();
    loading_.store(true);
    current_target_ = std::string(table::kTxLookup.name);
    current_key_.clear();
    log_lck.unlock();

    auto target = txn.rw_cursor_dup_sort(table::kTxLookup);  // note: not a multi-value table
    collector_->load(*target, nullptr,
                     target->empty() ? MDBX_put_flags_t::MDBX_APPEND : MDBX_put_flags_t::MDBX_UPSERT);

    log_lck.lock();
    loading_.store(false);
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    collector_.reset();
    log_lck.unlock();
}

void TxLookup::unwind_impl(RWTxn& txn, BlockNum from, BlockNum to) {
    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::kUnwind;
    loading_.store(false);
    collector_ = std::make_unique<Collector>(etl_settings_);
    current_source_ = std::string(table::kBlockBodies.name);
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();

    // Into etl collector
    collect_transaction_hashes_from_canonical_bodies(txn, from, to, /*for_deletion=*/true);

    log_lck.lock();
    loading_.store(true);
    current_target_ = std::string(table::kTxLookup.name);
    current_key_.clear();
    log_lck.unlock();

    auto target = txn.rw_cursor_dup_sort(table::kTxLookup);  // note: not a multi-value table
    collector_->load(*target, nullptr, MDBX_put_flags_t::MDBX_UPSERT);

    log_lck.lock();
    loading_.store(false);
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    collector_.reset();
    log_lck.unlock();
}

void TxLookup::prune_impl(RWTxn& txn, BlockNum from, BlockNum to) {
    const MapConfig source_config{table::kBlockBodies};

    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::kPrune;
    loading_.store(false);
    collector_ = std::make_unique<Collector>(etl_settings_);
    current_source_ = std::string(source_config.name);
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();

    // Into etl collector
    collect_transaction_hashes_from_canonical_bodies(txn, from, to, /*for_deletion=*/true);

    log_lck.lock();
    loading_.store(true);
    current_target_ = std::string(table::kTxLookup.name);
    current_key_.clear();
    log_lck.unlock();

    auto target = txn.rw_cursor_dup_sort(table::kTxLookup);  // note: not a multi-value table
    collector_->load(*target, nullptr, MDBX_put_flags_t::MDBX_UPSERT);

    log_lck.lock();
    loading_.store(false);
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    collector_.reset();
    log_lck.unlock();
}

void TxLookup::collect_transaction_hashes_from_canonical_bodies(RWTxn& txn,
                                                                const BlockNum from, const BlockNum to,
                                                                const bool for_deletion) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    DataModel data_model = data_model_factory_(txn);

    BlockNum target_block_num{std::max(from, to)};
    BlockNum start_block_num{std::min(from, to) + 1};

    Bytes etl_value{};

    for (BlockNum current_block_num = start_block_num; current_block_num <= target_block_num; ++current_block_num) {
        auto current_hash = read_canonical_header_hash(txn, current_block_num);
        if (!current_hash) throw StageError(Stage::Result::kBadChainSequence,
                                            "Canonical hash at block_num " + std::to_string(current_block_num) + " not found");
        std::vector<Bytes> rlp_encoded_txs;
        auto found = data_model.read_rlp_transactions(current_block_num, *current_hash, rlp_encoded_txs);
        if (!found) throw StageError(Stage::Result::kBadChainSequence,
                                     "Canonical block at block_num " + std::to_string(current_block_num) + " not found");

        // Log and abort check
        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            std::unique_lock log_lck(sl_mutex_);
            current_key_ = std::to_string(current_block_num);
            log_time = now + 5s;
        }

        if (rlp_encoded_txs.empty()) continue;

        // The same loop is used for forward and for unwind
        // In the latter two records must be deleted hence we set etl_value only if deletion is not required
        if (!for_deletion) {
            Bytes block_num_as_bytes(sizeof(BlockNum), '\0');
            endian::store_big_u64(block_num_as_bytes.data(), current_block_num);
            etl_value.assign(zeroless_view(block_num_as_bytes));
        }

        for (auto& rlp_encoded_tx : rlp_encoded_txs) {
            // Hash transaction rlp
            auto transaction_hash = keccak256(rlp_encoded_tx);  // see Transaction::hash()
            collector_->collect({Bytes(transaction_hash.bytes, kHashLength), etl_value});
        }
    }
}

std::vector<std::string> TxLookup::get_log_progress() {
    std::vector<std::string> ret{"op", std::string(magic_enum::enum_name<OperationType>(operation_))};
    std::unique_lock log_lck(sl_mutex_);
    if (current_source_.empty() && current_target_.empty()) {
        ret.insert(ret.end(), {"db", "waiting ..."});
    } else {
        if (loading_) {
            current_key_ = collector_ ? abridge(collector_->get_load_key(), kAddressLength) : "";
            ret.insert(ret.end(), {"from", "etl", "to", current_target_, "key", current_key_});
        } else {
            ret.insert(ret.end(), {"from", current_source_, "to", "etl", "key", current_key_});
        }
    }
    return ret;
}

void TxLookup::reset_log_progress() {
    std::unique_lock log_lck(sl_mutex_);
    loading_ = false;
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
}
}  // namespace silkworm::stagedsync
