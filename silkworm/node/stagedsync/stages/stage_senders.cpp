// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stage_senders.hpp"

#include <algorithm>
#include <stdexcept>
#include <thread>

#include <gsl/util>
#include <magic_enum.hpp>

#include <silkworm/core/crypto/ecdsa.h>
#include <silkworm/core/crypto/secp256k1n.hpp>
#include <silkworm/core/protocol/validation.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/infra/common/stopwatch.hpp>

namespace silkworm::stagedsync {

using namespace std::chrono_literals;
using namespace silkworm::db;
using silkworm::datastore::kvdb::from_slice;
using silkworm::datastore::kvdb::to_slice;

Senders::Senders(
    SyncContext* sync_context,
    DataModelFactory data_model_factory,
    const ChainConfig& chain_config,
    size_t batch_size,
    datastore::etl::CollectorSettings etl_settings,
    BlockAmount prune_mode_senders)
    : Stage(sync_context, stages::kSendersKey),
      data_model_factory_(std::move(data_model_factory)),
      chain_config_(chain_config),
      prune_mode_senders_(prune_mode_senders),
      max_batch_size_{batch_size / std::thread::hardware_concurrency() / sizeof(AddressRecovery)},
      batch_{std::make_shared<std::vector<AddressRecovery>>()},
      etl_settings_(std::move(etl_settings)) {
    // Reserve space for max batch in advance
    batch_->reserve(max_batch_size_);
}

Stage::Result Senders::forward(RWTxn& txn) {
    std::unique_lock log_lock(sl_mutex_);
    operation_ = OperationType::kForward;
    total_processed_blocks_ = 0;
    total_collected_transactions_ = 0;
    log_lock.unlock();

    collector_ = std::make_unique<datastore::kvdb::Collector>(etl_settings_);

    const auto res{parallel_recover(txn)};
    if (res == Stage::Result::kSuccess) {
        txn.commit_and_renew();
    }

    log_lock.lock();
    operation_ = OperationType::kNone;
    log_lock.unlock();

    collector_.reset();

    return res;
}

Stage::Result Senders::unwind(RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};

    if (!sync_context_->unwind_point.has_value()) return ret;
    const BlockNum to{sync_context_->unwind_point.value()};

    operation_ = OperationType::kUnwind;
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
        const auto bodies_stage_progress{stages::read_stage_progress(txn, stages::kBlockBodiesKey)};
        if (previous_progress <= to || bodies_stage_progress <= to) {
            // Nothing to process
            operation_ = OperationType::kNone;
            return ret;
        }

        const BlockNum segment_width{previous_progress - to};
        if (segment_width > stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(previous_progress),
                       "to", std::to_string(to),
                       "span", std::to_string(segment_width)});
        }

        auto unwind_cursor = txn.rw_cursor(table::kSenders);
        const auto start_key{block_key(to + 1)};
        size_t erased{0};
        auto data{unwind_cursor->lower_bound(to_slice(start_key), /*throw_notfound=*/false)};
        while (data) {
            // Log and abort check
            if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
                throw_if_stopping();
                std::unique_lock log_lck(sl_mutex_);
                const auto reached_block_num{endian::load_big_u64(from_slice(data.key).data())};
                current_key_ = std::to_string(reached_block_num);
                log_time = now + 5s;
            }
            unwind_cursor->erase();
            ++erased;
            data = unwind_cursor->to_next(/*throw_notfound=*/false);
        }
        if (sw) {
            const auto [_, duration]{sw->lap()};
            log::Trace(log_prefix_,
                       {"origin", table::kSenders.name_str(),
                        "erased", std::to_string(erased),
                        "in", StopWatch::format(duration)});
        }

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
    return ret;
}

Stage::Result Senders::prune(RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    operation_ = OperationType::kPrune;
    current_key_.clear();
    std::unique_ptr<StopWatch> sw;
    if (log::test_verbosity(log::Level::kTrace)) {
        sw = std::make_unique<StopWatch>(/*auto_start=*/true);
    }

    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    try {
        throw_if_stopping();
        if (!prune_mode_senders_.enabled()) {
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
        const auto prune_threshold{prune_mode_senders_.value_from_head(forward_progress)};
        if (!prune_threshold) {
            operation_ = OperationType::kNone;
            return ret;
        }

        const BlockNum segment_width{forward_progress - prune_progress};
        if (segment_width > stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(prune_progress),
                       "to", std::to_string(forward_progress),
                       "threshold", std::to_string(prune_threshold)});
        }

        auto prune_cursor = txn.rw_cursor(table::kSenders);
        const auto upper_key{block_key(prune_threshold)};
        size_t erased{0};
        auto prune_data{prune_cursor->lower_bound(to_slice(upper_key), /*throw_notfound=*/false)};
        while (prune_data) {
            const auto reached_block_num{endian::load_big_u64(from_slice(prune_data.key).data())};
            // Log and abort check
            if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
                throw_if_stopping();
                std::unique_lock log_lck(sl_mutex_);
                current_key_ = std::to_string(reached_block_num);
                log_time = now + 5s;
            }
            if (reached_block_num <= prune_threshold) {
                prune_cursor->erase();
                ++erased;
            }
            prune_data = prune_cursor->to_previous(/*throw_notfound=*/false);
        }

        throw_if_stopping();
        if (sw) {
            const auto [_, duration]{sw->lap()};
            log::Trace(log_prefix_, {"source", table::kSenders.name_str(), "erased", std::to_string(erased), "in", StopWatch::format(duration)});
        }
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

void Senders::set_prune_mode_senders(BlockAmount prune_mode_senders) {
    prune_mode_senders_ = prune_mode_senders;
}

Stage::Result Senders::parallel_recover(RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};

    collected_senders_ = 0;
    collector_->clear();
    batch_->clear();
    results_.clear();

    try {
        DataModel data_model = data_model_factory_(txn);

        // Check stage boundaries using previous execution of current stage and current execution of previous stage
        auto previous_progress{stages::read_stage_progress(txn, stages::kSendersKey)};
        auto block_hashes_progress{stages::read_stage_progress(txn, stages::kBlockHashesKey)};
        auto block_bodies_progress{stages::read_stage_progress(txn, stages::kBlockBodiesKey)};
        auto target_block_num{std::min(block_hashes_progress, block_bodies_progress)};
        // note: it would be better to use sync_context_->target_block_num instead of target_block

        const BlockNum segment_width{target_block_num - previous_progress};
        if (segment_width > stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_, {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                                    "from", std::to_string(previous_progress),
                                    "to", std::to_string(target_block_num),
                                    "span", std::to_string(segment_width),
                                    "max_batch_size", std::to_string(max_batch_size_)});
        }

        if (previous_progress == target_block_num) {
            // Nothing to process
            return ret;
        }
        if (previous_progress > target_block_num) {
            // Something bad had happened. Maybe we need to unwind ?
            throw StageError(Stage::Result::kInvalidProgress, "Previous progress " + std::to_string(previous_progress) +
                                                                  " > target progress " + std::to_string(target_block_num));
        }

        static secp256k1_context* context = secp256k1_context_create(SILKWORM_SECP256K1_CONTEXT_FLAGS);
        if (!context) throw std::runtime_error("Could not create elliptic curve context");

        BlockNum start_block_num{previous_progress + 1u};

        // Create the pool of worker threads crunching the address recovery tasks
        ThreadPool worker_pool;

        // Load block transactions from db and recover tx senders in batches
        uint64_t total_collected_senders{0};
        uint64_t total_empty_blocks{0};

        // Start from first block and read all in sequence
        for (auto current_block_num = start_block_num; current_block_num <= target_block_num; ++current_block_num) {
            const auto current_hash = read_canonical_header_hash(txn, current_block_num);
            if (!current_hash) throw StageError(Stage::Result::kBadChainSequence,
                                                "Canonical hash at block_num " + std::to_string(current_block_num) + " not found");
            const auto block_header = data_model.read_header(current_block_num, *current_hash);
            if (!block_header) throw StageError(Stage::Result::kBadChainSequence,
                                                "Canonical header at block_num " + std::to_string(current_block_num) + " not found");
            BlockBody block_body;
            const auto found = data_model.read_body(*current_hash, current_block_num, block_body);
            if (!found) throw StageError(Stage::Result::kBadChainSequence,
                                         "Canonical body at block_num " + std::to_string(current_block_num) + " not found");

            // Every 1024 blocks check if the SignalHandler has been triggered
            if ((current_block_num % 1024 == 0) && is_stopping()) {
                throw StageError(Stage::Result::kAborted);
            }

            // Get the body and its transactions
            if (block_body.transactions.empty()) {
                ++total_empty_blocks;
                continue;
            }

            total_collected_senders += block_body.transactions.size();
            success_or_throw(add_to_batch(current_block_num, block_header->timestamp, *current_hash, block_body.transactions));

            // Process batch in parallel if max size has been reached
            if (batch_->size() >= max_batch_size_) {
                increment_total_collected_transactions(batch_->size());
                recover_batch(worker_pool, context);
            }
        }

        // Recover last incomplete batch [likely]
        if (!batch_->empty()) {
            increment_total_collected_transactions(batch_->size());
            recover_batch(worker_pool, context);
        }

        // Wait for all senders to be recovered and collected in ETL
        while (collected_senders_ != total_collected_senders) {
            collect_senders();
            std::this_thread::sleep_for(1ms);
        }

        ensure(collector_->size() + total_empty_blocks == segment_width,
               [&]() { return "Senders: invalid number of ETL keys expected=" + std::to_string(segment_width) +
                              "got=" + std::to_string(collector_->size() + total_empty_blocks); });

        // Store all recovered senders into db
        log::Trace(log_prefix_, {"op", "store senders", "reached_block_num", std::to_string(target_block_num)});
        store_senders(txn);

        // Update stage progress with last reached block number
        stages::write_stage_progress(txn, stages::kSendersKey, target_block_num);
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

    return ret;
}

Stage::Result Senders::add_to_batch(BlockNum block_num, BlockTime block_timestamp, const Hash& block_hash, const std::vector<Transaction>& transactions) {
    if (is_stopping()) {
        return Stage::Result::kAborted;
    }

    const evmc_revision rev{chain_config_.revision(block_num, block_timestamp)};
    const bool has_homestead{rev >= EVMC_HOMESTEAD};
    const bool has_spurious_dragon{rev >= EVMC_SPURIOUS_DRAGON};

    uint32_t tx_id{0};
    for (const auto& transaction : transactions) {
        if (!protocol::transaction_type_is_supported(transaction.type, rev)) {
            log::Error(log_prefix_) << "Transaction type " << magic_enum::enum_name<TransactionType>(transaction.type)
                                    << " for transaction #" << tx_id << " in block #" << block_num << " before it's supported";
            return Stage::Result::kInvalidTransaction;
        }

        if (!is_valid_signature(transaction.r, transaction.s, has_homestead)) {
            log::Error(log_prefix_) << "Got invalid signature for transaction #" << tx_id << " in block #" << block_num;
            return Stage::Result::kInvalidTransaction;
        }

        if (transaction.chain_id.has_value()) {
            if (!has_spurious_dragon) {
                log::Error(log_prefix_) << "EIP-155 signature for transaction #" << tx_id << " in block #" << block_num
                                        << " before Spurious Dragon";
                return Stage::Result::kInvalidTransaction;
            }
            if (transaction.chain_id.value() != chain_config_.chain_id) {
                log::Error(log_prefix_) << "EIP-155 invalid signature for transaction #" << tx_id << " in block #" << block_num;
                return Stage::Result::kInvalidTransaction;
            }
        }

        Bytes rlp{};
        transaction.encode_for_signing(rlp);

        batch_->push_back(AddressRecovery{block_num, block_hash, transaction.odd_y_parity});
        intx::be::unsafe::store(batch_->back().tx_signature, transaction.r);
        intx::be::unsafe::store(batch_->back().tx_signature + kHashLength, transaction.s);
        batch_->back().rlp = std::move(rlp);

        ++tx_id;
    }
    increment_total_processed_blocks();

    return is_stopping() ? Stage::Result::kAborted : Stage::Result::kSuccess;
}

void Senders::recover_batch(ThreadPool& worker_pool, const secp256k1_context* context) {
    // Launch parallel senders recovery
    log::Trace(log_prefix_, {"op", "recover_batch", "first", std::to_string(batch_->cbegin()->block_num)});

    StopWatch sw;
    const auto start = sw.start();

    // Wait until total unfinished tasks in worker pool falls below 2 * num workers
    const size_t max_unfinished_tasks = 2 * worker_pool.get_thread_count();
    while (worker_pool.get_tasks_total() >= max_unfinished_tasks) {
        std::this_thread::sleep_for(1ms);
    }

    // Swap the waiting batch w/ an empty one and submit a new recovery task to the worker pool
    std::shared_ptr<std::vector<AddressRecovery>> ready_batch{std::make_shared<std::vector<AddressRecovery>>()};
    ready_batch->reserve(max_batch_size_);
    ready_batch.swap(batch_);
    auto batch_result = worker_pool.submit([=]() {
        std::for_each(ready_batch->begin(), ready_batch->end(), [&](auto& package) {
            const auto tx_hash{keccak256(package.rlp)};
            const bool ok = silkworm_recover_address(package.tx_from.bytes, tx_hash.bytes, package.tx_signature, package.odd_y_parity, context);
            if (!ok) {
                throw std::runtime_error("Unable to recover from address in block " + std::to_string(package.block_num));
            }
        });
        return ready_batch;
    });
    results_.emplace_back(std::move(batch_result));

    // Check completed batch of senders and collect them
    collect_senders();

    const auto [end, _] = sw.lap();
    log::Trace(log_prefix_, {"op", "recover_batch", "elapsed", StopWatch::format(end - start)});

    if (is_stopping()) throw StageError(Stage::Result::kAborted);
}

void Senders::collect_senders() {
    std::erase_if(results_, [&](auto& future_completed_batch) {
        if (future_completed_batch.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
            auto completed_batch = future_completed_batch.get();
            // Put recovered senders into ETL
            collect_senders(completed_batch);
            // Update count of collected senders
            collected_senders_ += completed_batch->size();
            return true;
        }
        return false;
    });
}

void Senders::collect_senders(std::shared_ptr<AddressRecoveryBatch>& batch) {
    StopWatch sw;
    const auto start = sw.start();

    BlockNum block_num{0};
    Bytes key;
    Bytes value;
    for (const auto& package : *batch) {
        if (package.block_num != block_num) {
            if (!key.empty()) {
                collector_->collect({key, value});
                key.clear();
                value.clear();
            }
            key = block_key(package.block_num, package.block_hash.bytes);
            value.clear();
            block_num = package.block_num;
        }
        value.append(package.tx_from.bytes, sizeof(evmc::address));
    }
    if (!key.empty()) {
        collector_->collect({key, value});
        key.clear();
        value.clear();
    }
    const auto [end, _] = sw.lap();
    log::Trace(log_prefix_, {"op", "store_senders", "elapsed", StopWatch::format(end - start)});

    if (is_stopping()) throw StageError(Stage::Result::kAborted);
}

void Senders::store_senders(RWTxn& txn) {
    if (!collector_->empty()) {
        log::Trace(log_prefix_, {"load ETL items", std::to_string(collector_->size())});
        // Prepare target table
        auto senders_cursor = txn.rw_cursor_dup_sort(table::kSenders);
        log::Trace(log_prefix_, {"load ETL data", human_size(collector_->bytes_size())});
        collector_->load(*senders_cursor, nullptr, MDBX_put_flags_t::MDBX_APPEND);
    }
}

std::vector<std::string> Senders::get_log_progress() {
    std::unique_lock lock{mutex_};
    switch (operation_) {
        case OperationType::kForward: {
            return {"blocks", std::to_string(total_processed_blocks_),
                    "transactions", std::to_string(total_collected_transactions_)};
        }
        default:
            return {"key", current_key_};
    }
}

void Senders::increment_total_processed_blocks() {
    std::unique_lock lock{mutex_};
    ++total_processed_blocks_;
}

void Senders::increment_total_collected_transactions(size_t delta) {
    std::unique_lock lock{mutex_};
    total_collected_transactions_ += delta;
}

}  // namespace silkworm::stagedsync
