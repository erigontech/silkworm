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

#include "stage_tx_lookup.hpp"

#include <silkworm/common/endian.hpp>
#include <silkworm/db/access_layer.hpp>

namespace silkworm::stagedsync {

Stage::Result TxLookup::forward(db::RWTxn& txn) {
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
                             "TxLookup progress " + std::to_string(previous_progress) +
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
        if (!previous_progress && node_settings_->prune_mode->tx_index().enabled())
            previous_progress = node_settings_->prune_mode->tx_index().value_from_head(target_progress);

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
    collector_.reset();
    return ret;
}

Stage::Result TxLookup::unwind(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};

    if (!sync_context_->unwind_point.has_value()) return ret;
    const BlockNum to{sync_context_->unwind_point.value()};

    operation_ = OperationType::Unwind;
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        const auto execution_progress{db::stages::read_stage_progress(*txn, db::stages::kExecutionKey)};
        if (previous_progress <= to || execution_progress <= to) {
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

    operation_ = OperationType::None;
    collector_.reset();
    return ret;
}

Stage::Result TxLookup::prune(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::Prune;

    try {
        throw_if_stopping();
        if (!node_settings_->prune_mode->tx_index().enabled()) {
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
        const auto prune_threshold{node_settings_->prune_mode->tx_index().value_from_head(forward_progress)};
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
            const auto previous_prune_threshold{
                node_settings_->prune_mode->tx_index().value_from_head(prune_progress)};
            prune_impl(txn, previous_prune_threshold, prune_threshold);
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

    operation_ = OperationType::None;
    return ret;
}

void TxLookup::forward_impl(db::RWTxn& txn, const BlockNum from, const BlockNum to) {
    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::Forward;
    loading_ = false;
    collector_ = std::make_unique<etl::Collector>(node_settings_);
    current_source_ = std::string(db::table::kBlockBodies.name);
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();

    // Into etl collector
    collect_transaction_hashes_from_canonical_bodies(txn, from, to, /*for_deletion=*/false);

    log_lck.lock();
    loading_ = true;
    current_target_ = std::string(db::table::kTxLookup.name);
    current_key_.clear();
    log_lck.unlock();

    db::Cursor target(txn, db::table::kTxLookup);
    collector_->load(target, nullptr,
                     target.empty() ? MDBX_put_flags_t::MDBX_APPEND : MDBX_put_flags_t::MDBX_UPSERT);

    log_lck.lock();
    loading_ = false;
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    collector_.reset();
    log_lck.unlock();
}

void TxLookup::unwind_impl(db::RWTxn& txn, BlockNum from, BlockNum to) {
    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::Unwind;
    loading_ = false;
    collector_ = std::make_unique<etl::Collector>(node_settings_);
    current_source_ = std::string(db::table::kBlockBodies.name);
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();

    // Into etl collector
    collect_transaction_hashes_from_canonical_bodies(txn, from, to, /*for_deletion=*/true);

    log_lck.lock();
    loading_ = true;
    current_target_ = std::string(db::table::kTxLookup.name);
    current_key_.clear();
    log_lck.unlock();

    db::Cursor target(txn, db::table::kTxLookup);
    collector_->load(target, nullptr, MDBX_put_flags_t::MDBX_UPSERT);

    log_lck.lock();
    loading_ = false;
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    collector_.reset();
    log_lck.unlock();
}

void TxLookup::prune_impl(db::RWTxn& txn, BlockNum from, BlockNum to) {
    const db::MapConfig source_config{db::table::kBlockBodies};

    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::Prune;
    loading_ = false;
    collector_ = std::make_unique<etl::Collector>(node_settings_);
    current_source_ = std::string(source_config.name);
    current_target_.clear();
    current_key_.clear();
    log_lck.unlock();

    // Into etl collector
    collect_transaction_hashes_from_canonical_bodies(txn, from, to, /*for_deletion=*/true);

    log_lck.lock();
    loading_ = true;
    current_target_ = std::string(db::table::kTxLookup.name);
    current_key_.clear();
    log_lck.unlock();

    db::Cursor target(txn, db::table::kTxLookup);
    collector_->load(target, nullptr, MDBX_put_flags_t::MDBX_UPSERT);

    log_lck.lock();
    loading_ = false;
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
    collector_.reset();
    log_lck.unlock();
}

void TxLookup::collect_transaction_hashes_from_canonical_bodies(db::RWTxn& txn,
                                                                const BlockNum from, const BlockNum to,
                                                                const bool for_deletion) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    const BlockNum max_block_number{std::max(from, to)};
    BlockNum expected_block_number{std::min(from, to) + 1};
    BlockNum reached_block_number{0};

    auto start_key{db::block_key(expected_block_number)};
    Bytes etl_value{};
    db::Cursor canonicals(txn, db::table::kCanonicalHashes);
    db::Cursor bodies(txn, db::table::kBlockBodies);
    db::Cursor transactions{txn, db::table::kBlockTransactions};

    auto canonical_data{canonicals.find(db::to_slice(start_key), /*throw_notfound=*/false)};
    if (!canonical_data) {
        throw StageError(Stage::Result::kBadChainSequence,
                         "Missing canonical hash for block " + std::to_string(expected_block_number));
    }
    while (canonical_data) {
        reached_block_number = endian::load_big_u64(static_cast<const uint8_t*>(canonical_data.key.data()));
        check_block_sequence(reached_block_number, expected_block_number);
        if (reached_block_number > max_block_number) break;

        // Log and abort check
        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            std::unique_lock log_lck(sl_mutex_);
            current_key_ = std::to_string(reached_block_number);
            log_time = now + 5s;
        }

        if (canonical_data.value.length() != kHashLength) {
            throw StageError(Stage::Result::kDbError,
                             "Invalid value length for canonical hash at block " + std::to_string(reached_block_number));
        }

        const evmc::bytes32 header_hash{to_bytes32(db::from_slice(canonical_data.value))};
        const auto body_key{db::block_key(reached_block_number, header_hash.bytes)};
        const auto body_data{bodies.find(db::to_slice(body_key), /*throw_notfound=*/false)};
        if (!body_data) {
            throw StageError(Stage::Result::kDbError,
                             "Could not load block body " + std::to_string(reached_block_number));
        }
        auto body_data_key_view{db::from_slice(body_data.key)};
        auto body_data_value_view{db::from_slice(body_data.value)};
        const auto block_body{db::detail::decode_stored_block_body(body_data_value_view)};
        if (block_body.txn_count) {
            // The same loop is used for forward and for unwind
            // In the latter two records must be deleted hence we set etl_value only if deletion
            // is not required
            if (!for_deletion) {
                etl_value.assign(zeroless_view(body_data_key_view.substr(0, sizeof(BlockNum))));
            }

            size_t max_transaction_id{block_body.base_txn_id + block_body.txn_count - 1};
            size_t processed_transactions{0};

            const Bytes transactions_base_key{db::block_key(block_body.base_txn_id)};
            auto transactions_data{
                transactions.lower_bound(db::to_slice(transactions_base_key), /*throw_notfound=*/false)};
            while (transactions_data) {
                const auto reached_transaction_id{
                    endian::load_big_u64(static_cast<uint8_t*>(transactions_data.key.data()))};
                if (reached_transaction_id > max_transaction_id) break;

                // Hash transaction rlp
                auto transaction_data_value_view{db::from_slice(transactions_data.value)};
                auto transaction_hash{keccak256(transaction_data_value_view)};
                collector_->collect({Bytes(transaction_hash.bytes, kHashLength), etl_value});

                ++processed_transactions;
                transactions_data = transactions.to_next(/*throw_notfound=*/false);
            }

            if (processed_transactions != block_body.txn_count) {
                log::Error("Mismatching tx count",
                           {"block", std::to_string(reached_block_number),
                            "expected txs", std::to_string(block_body.txn_count),
                            "got", std::to_string(processed_transactions)});
                throw std::runtime_error("Mismatching tx count");
            }
        }

        ++expected_block_number;
        canonical_data = canonicals.to_next(/*throw_notfound=*/false);
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
