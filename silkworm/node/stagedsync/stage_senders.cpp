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

#include <algorithm>
#include <stdexcept>
#include <thread>

#include <gsl/util>
#include <silkpre/secp256k1n.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/node/db/access_layer.hpp>

namespace silkworm::stagedsync {

Senders::Senders(NodeSettings* node_settings, SyncContext* sync_context)
    : Stage(sync_context, db::stages::kSendersKey, node_settings),
      max_batch_size_{node_settings->batch_size / std::thread::hardware_concurrency() / sizeof(AddressRecovery)},
      batch_{std::make_shared<std::vector<AddressRecovery>>()},
      collector_{node_settings} {
    // Reserve space for max batch in advance
    batch_->reserve(max_batch_size_);
}

Stage::Result Senders::forward(db::RWTxn& txn) {
    std::unique_lock log_lock(sl_mutex_);
    operation_ = OperationType::Forward;
    log_lock.unlock();

    const auto res{parallel_recover(txn)};
    if (res == Stage::Result::kSuccess) {
        txn.commit();
    }

    log_lock.lock();
    operation_ = OperationType::None;
    log_lock.unlock();

    return res;
}

Stage::Result Senders::unwind(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};

    if (!sync_context_->unwind_point.has_value()) return ret;
    const BlockNum to{sync_context_->unwind_point.value()};

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
        const auto bodies_stage_progress{db::stages::read_stage_progress(txn, db::stages::kBlockBodiesKey)};
        if (previous_progress <= to || bodies_stage_progress <= to) {
            // Nothing to process
            operation_ = OperationType::None;
            return ret;
        }

        const BlockNum segment_width{previous_progress - to};
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(previous_progress),
                       "to", std::to_string(to),
                       "span", std::to_string(segment_width)});
        }

        db::PooledCursor unwind_table(txn, db::table::kSenders);
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

Stage::Result Senders::prune(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
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
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(prune_progress),
                       "to", std::to_string(forward_progress),
                       "threshold", std::to_string(prune_threshold)});
        }

        db::PooledCursor prune_table(txn, db::table::kSenders);
        const auto upper_key{db::block_key(prune_threshold)};
        size_t erased{0};
        auto prune_data{prune_table.lower_bound(db::to_slice(upper_key), /*throw_notfound=*/false)};
        while (prune_data) {
            const auto reached_block_number{endian::load_big_u64(db::from_slice(prune_data.key).data())};
            // Log and abort check
            if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
                throw_if_stopping();
                std::unique_lock log_lck(sl_mutex_);
                current_key_ = std::to_string(reached_block_number);
                log_time = now + 5s;
            }
            if (reached_block_number <= prune_threshold) {
                prune_table.erase();
                ++erased;
            }
            prune_data = prune_table.to_previous(/*throw_notfound=*/false);
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

Stage::Result Senders::parallel_recover(db::RWTxn& txn) {
    Stage::Result ret{Stage::Result::kSuccess};
    try {
        // Check stage boundaries using previous execution of current stage and current execution of previous stage
        auto previous_progress{db::stages::read_stage_progress(txn, db::stages::kSendersKey)};
        auto block_hashes_progress{db::stages::read_stage_progress(txn, db::stages::kBlockHashesKey)};
        auto block_bodies_progress{db::stages::read_stage_progress(txn, db::stages::kBlockBodiesKey)};
        auto target_progress{std::min(block_hashes_progress, block_bodies_progress)};

        if (previous_progress == target_progress) {
            // Nothing to process
            return ret;
        } else if (previous_progress > target_progress) {
            // Something bad had happened. Maybe we need to unwind ?
            throw StageError(Stage::Result::kInvalidProgress, "Previous progress " + std::to_string(previous_progress) +
                                                                  " > target progress " + std::to_string(target_progress));
        }

        log::Info(log_prefix_, {"op", "parallel_recover",
                                "num_threads", std::to_string(std::thread::hardware_concurrency()), "max_batch_size", std::to_string(max_batch_size_)});

        secp256k1_context* context = secp256k1_context_create(SILKPRE_SECP256K1_CONTEXT_FLAGS);
        if (!context) throw std::runtime_error("Could not create elliptic curve context");
        auto _ = gsl::finally([&]() { if (context) std::free(context); });

        BlockNum from{previous_progress + 1u};

        // Load canonical headers from db
        log::Trace(log_prefix_, {"op", "read canonical hashes", "from", std::to_string(from), "to", std::to_string(target_progress)});

        success_or_throw(read_canonical_hashes(txn, from, target_progress));

        // Create the pool of worker threads crunching the address recovery tasks
        thread_pool worker_pool;

        // Load block transactions from db and recover tx senders in batches
        log::Trace(log_prefix_, {"op", "read bodies", "from", std::to_string(from), "to", std::to_string(target_progress)});

        auto bodies_cursor = txn.ro_cursor(db::table::kBlockBodies);
        auto transactions_cursor = txn.ro_cursor(db::table::kBlockTransactions);

        uint64_t total_collected_senders{0};

        // Start from first block and read all in sequence
        BlockNum reached_block_num{0};
        BlockNum expected_block_num{from};
        auto block_hash_it{canonical_hashes_.begin()};
        auto bodies_initial_key{db::block_key(from, block_hash_it->bytes)};
        auto body_data{bodies_cursor->find(db::to_slice(bodies_initial_key), false)};
        while (body_data.done) {
            auto body_data_key_view{db::from_slice(body_data.key)};
            reached_block_num = endian::load_big_u64(body_data_key_view.data());
            if (reached_block_num < expected_block_num) {
                // The same block height has been recorded but is not canonical, move to next and continue
                body_data = bodies_cursor->to_next(false);
                continue;
            } else if (reached_block_num > expected_block_num) {
                // We exceeded the expected block hence 1) the db misses a block or 2) blocks are not stored sequentially
                throw StageError(Stage::Result::kBadChainSequence,
                                 "Expected block " + std::to_string(expected_block_num) +
                                     " got " + std::to_string(reached_block_num));
            }

            if (memcmp(&body_data_key_view[8], block_hash_it->bytes, sizeof(kHashLength)) != 0) {
                // We stumbled into a non-canonical block (not matching header), move to next and continue
                body_data = bodies_cursor->to_next(false);
                continue;
            }

            // Every 1024 blocks check if the SignalHandler has been triggered
            if ((reached_block_num % 1024 == 0) && is_stopping()) {
                throw StageError(Stage::Result::kAborted);
            }

            // Get the body and its transactions
            auto body_rlp{db::from_slice(body_data.value)};
            auto block_body{db::detail::decode_stored_block_body(body_rlp)};
            if (block_body.txn_count) {
                std::vector<Transaction> transactions;
                db::read_transactions(*transactions_cursor, block_body.base_txn_id, block_body.txn_count, transactions);
                total_collected_senders += transactions.size();
                success_or_throw(add_to_batch(reached_block_num, std::move(transactions)));

                // Process batch in parallel if max size has been reached
                if (batch_->size() >= max_batch_size_) {
                    increment_total_collected_transactions(batch_->size());
                    recover_batch(worker_pool, context, from);
                }
            }

            // After processing move to next block number and header
            if (++block_hash_it == canonical_hashes_.end()) {
                // We'd go beyond collected canonical headers
                break;
            }
            expected_block_num++;
            body_data = bodies_cursor->to_next(false);
        }

        // Recover last incomplete batch [likely]
        if (!batch_->empty()) {
            increment_total_collected_transactions(batch_->size());
            recover_batch(worker_pool, context, from);
        }

        // Wait for all senders to be recovered and collected in ETL
        while (collected_senders_ != total_collected_senders) {
            collect_senders(from);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // Store all recovered senders into db
        log::Trace(log_prefix_, {"op", "store senders", "reached_block_num", std::to_string(reached_block_num)});
        store_senders(txn);

        // Update stage progress with last reached block number
        db::stages::write_stage_progress(txn, db::stages::kSendersKey, reached_block_num);
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

Stage::Result Senders::read_canonical_hashes(db::ROTxn& txn, BlockNum from, BlockNum to) noexcept {
    std::unique_ptr<StopWatch> sw;
    if (log::test_verbosity(log::Level::kTrace)) {
        sw = std::make_unique<StopWatch>(/*auto_start=*/true);
    }

    canonical_hashes_.clear();

    uint64_t headers_count{to - from};
    canonical_hashes_.reserve(headers_count);
    if (headers_count > 16) {
        log::Info(log_prefix_, {"collecting", "headers", "from", std::to_string(from), "to", std::to_string(to)});
    }

    // Locate starting canonical header selected
    BlockNum reached_block_num{0};
    BlockNum expected_block_num{from};

    // Enclose in try catch block as db cursor reads may fail
    try {
        auto hashes_cursor{db::open_cursor(*txn, db::table::kCanonicalHashes)};
        auto header_key{db::block_key(expected_block_num)};
        // Read all headers up to upper bound (included)
        auto header_data{hashes_cursor.find(db::to_slice(header_key), false)};
        while (header_data.done) {
            reached_block_num = endian::load_big_u64(static_cast<uint8_t*>(header_data.key.data()));
            SILKWORM_ASSERT(reached_block_num == expected_block_num);
            SILKWORM_ASSERT(header_data.value.length() == kHashLength);

            // We have a canonical header hash in right sequence
            canonical_hashes_.emplace_back(to_bytes32(db::from_slice(header_data.value)));
            if (reached_block_num == to) {
                break;
            }
            expected_block_num++;
            header_data = hashes_cursor.to_next(false);

            // Do we need to abort ?
            if ((expected_block_num % 1024 == 0) && is_stopping()) {
                return Stage::Result::kAborted;
            }
        }

        // If we've not reached block_to something is wrong
        if (reached_block_num != to) {
            log::Error(log_prefix_, {"expected block", std::to_string(to), "got", std::to_string(reached_block_num)});
            return Stage::Result::kBadChainSequence;
        }

        if (sw) {
            const auto [_, duration]{sw->stop()};
            log::Trace(log_prefix_,
                       {"collected block hashes", std::to_string(canonical_hashes_.size()), "in", StopWatch::format(duration)});
        }
        return is_stopping() ? Stage::Result::kAborted : Stage::Result::kSuccess;

    } catch (const mdbx::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return Stage::Result::kDbError;
    } catch (const std::exception& ex) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        return Stage::Result::kUnexpectedError;
    } catch (...) {
        log::Error(log_prefix_,
                   {"function", std::string(__FUNCTION__), "exception", "undefined"});
        return Stage::Result::kUnexpectedError;
    }
}

Stage::Result Senders::add_to_batch(BlockNum block_num, std::vector<Transaction>&& transactions) {
    if (is_stopping()) {
        return Stage::Result::kAborted;
    }

    // We're only interested in revisions up to London, so it's OK to not detect time-based forks.
    const evmc_revision rev{node_settings_->chain_config->revision(block_num, /*block_time=*/0)};
    const bool has_homestead{rev >= EVMC_HOMESTEAD};
    const bool has_spurious_dragon{rev >= EVMC_SPURIOUS_DRAGON};
    const bool has_berlin{rev >= EVMC_BERLIN};
    const bool has_london{rev >= EVMC_LONDON};

    uint32_t tx_id{0};
    for (const auto& transaction : transactions) {
        switch (transaction.type) {
            case Transaction::Type::kLegacy:
                break;
            case Transaction::Type::kEip2930:
                if (!has_berlin) {
                    log::Error(log_prefix_) << "Transaction type " << magic_enum::enum_name<Transaction::Type>(transaction.type)
                                            << " for transaction #" << tx_id << " in block #" << block_num << " before Berlin";
                    return Stage::Result::kInvalidTransaction;
                }
                break;
            case Transaction::Type::kEip1559:
                if (!has_london) {
                    log::Error(log_prefix_) << "Transaction type " << magic_enum::enum_name<Transaction::Type>(transaction.type)
                                            << " for transaction #" << tx_id << " in block #" << block_num << " before London";
                    return Stage::Result::kInvalidTransaction;
                }
                break;
        }

        if (!silkpre::is_valid_signature(transaction.r, transaction.s, has_homestead)) {
            log::Error(log_prefix_) << "Got invalid signature for transaction #" << tx_id << " in block #" << block_num;
            return Stage::Result::kInvalidTransaction;
        }

        if (transaction.chain_id.has_value()) {
            if (!has_spurious_dragon) {
                log::Error(log_prefix_) << "EIP-155 signature for transaction #" << tx_id << " in block #" << block_num
                                        << " before Spurious Dragon";
                return Stage::Result::kInvalidTransaction;
            } else if (transaction.chain_id.value() != node_settings_->chain_config->chain_id) {
                log::Error(log_prefix_) << "EIP-155 invalid signature for transaction #" << tx_id << " in block #" << block_num;
                return Stage::Result::kInvalidTransaction;
            }
        }

        Bytes rlp{};
        rlp::encode(rlp, transaction, /*for_signing=*/true, /*wrap_eip2718_into_string=*/false);

        batch_->push_back(AddressRecovery{block_num, transaction.odd_y_parity});
        intx::be::unsafe::store(batch_->back().tx_signature, transaction.r);
        intx::be::unsafe::store(batch_->back().tx_signature + kHashLength, transaction.s);
        batch_->back().rlp = std::move(rlp);

        ++tx_id;
    }
    increment_total_processed_blocks();

    return is_stopping() ? Stage::Result::kAborted : Stage::Result::kSuccess;
}

void Senders::recover_batch(thread_pool& worker_pool, secp256k1_context* context, BlockNum from) {
    // Launch parallel senders recovery
    log::Trace(log_prefix_, {"op", "recover_batch", "first", std::to_string(batch_->cbegin()->block_num)});

    StopWatch sw;
    const auto start = sw.start();

    // Wait until total unfinished tasks in worker pool falls below 2 * num workers
    static const auto kMaxUnfinishedTasks{2 * worker_pool.get_thread_count()};
    while (worker_pool.get_tasks_total() >= kMaxUnfinishedTasks) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Swap the waiting batch w/ an empty one and submit a new recovery task to the worker pool
    std::shared_ptr<std::vector<AddressRecovery>> ready_batch{std::make_shared<std::vector<AddressRecovery>>()};
    ready_batch->reserve(max_batch_size_);
    ready_batch.swap(batch_);
    auto batch_result = worker_pool.submit([=]() {
        std::for_each(ready_batch->begin(), ready_batch->end(), [&](auto& package) {
            const auto tx_hash{keccak256(package.rlp)};
            const bool ok = silkpre_recover_address(package.tx_from.bytes, tx_hash.bytes, package.tx_signature, package.odd_y_parity, context);
            if (!ok) {
                throw std::runtime_error("Unable to recover from address in block " + std::to_string(package.block_num));
            }
        });
        return ready_batch;
    });
    results_.emplace_back(std::move(batch_result));

    // Check completed batch of senders and collect them
    collect_senders(from);

    const auto [end, _] = sw.lap();
    log::Trace(log_prefix_, {"op", "recover_batch", "elapsed", sw.format(end - start)});

    if (is_stopping()) throw StageError(Stage::Result::kAborted);
}

void Senders::collect_senders(BlockNum from) {
    std::erase_if(results_, [&](auto& future_completed_batch) {
        if (future_completed_batch.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
            auto completed_batch = future_completed_batch.get();
            // Put recovered senders into ETL
            collect_senders(from, completed_batch);
            // Update count of collected senders
            collected_senders_ += completed_batch->size();
            return true;
        }
        return false;
    });
}

void Senders::collect_senders(BlockNum from, std::shared_ptr<AddressRecoveryBatch>& batch) {
    StopWatch sw;
    const auto start = sw.start();

    BlockNum block_num{0};
    Bytes key;
    Bytes value;
    for (const auto& package : *batch) {
        if (package.block_num != block_num) {
            if (!key.empty()) {
                collector_.collect({key, value});
                key.clear();
                value.clear();
            }
            block_num = package.block_num;
            key = db::block_key(block_num, canonical_hashes_.at(block_num - from).bytes);
            value.clear();
        }
        value.append(package.tx_from.bytes, sizeof(evmc::address));
    }
    if (!key.empty()) {
        collector_.collect({key, value});
        key.clear();
        value.clear();
    }
    const auto [end, _] = sw.lap();
    log::Trace(log_prefix_, {"op", "store_senders", "elapsed", sw.format(end - start)});

    if (is_stopping()) throw StageError(Stage::Result::kAborted);
}

void Senders::store_senders(db::RWTxn& txn) {
    if (!collector_.empty()) {
        log::Trace(log_prefix_, {"load ETL items", std::to_string(collector_.size())});
        // Prepare target table
        auto senders_cursor = txn.rw_cursor_dup_sort(db::table::kSenders);
        log::Trace(log_prefix_, {"load ETL data", human_size(collector_.bytes_size())});
        collector_.load(*senders_cursor, nullptr, MDBX_put_flags_t::MDBX_APPEND);
    }
}

std::vector<std::string> Senders::get_log_progress() {
    std::unique_lock lock{mutex_};
    switch (operation_) {
        case OperationType::Forward: {
            return {"block hashes", std::to_string(canonical_hashes_.size()),
                    "blocks", std::to_string(total_processed_blocks_),
                    "transactions", std::to_string(total_collected_transactions_)};
        }
        default:
            return {"key", current_key_};
    }
}

void Senders::increment_total_processed_blocks() {
    std::unique_lock lock{mutex_};
    total_processed_blocks_++;
}

void Senders::increment_total_collected_transactions(std::size_t delta) {
    std::unique_lock lock{mutex_};
    total_collected_transactions_ += delta;
}

}  // namespace silkworm::stagedsync
