/*
   Copyright 2020-2022 The Silkworm Authors

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

#include "recovery_farm.hpp"

#include <functional>
#include <mutex>

#include <silkworm/common/as_range.hpp>
#include <silkworm/common/assert.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>

namespace silkworm::stagedsync::recovery {

RecoveryFarm::RecoveryFarm(db::RWTxn& txn, NodeSettings* node_settings)
    : txn_{txn},
      node_settings_{node_settings},
      collector_(node_settings),
      batch_size_{node_settings->batch_size / std::thread::hardware_concurrency() / sizeof(RecoveryPackage)} {
    workers_.reserve(max_workers_);
    workers_connections_.reserve(max_workers_ * 2);  // One for task completed event and one for worker completed event
    batch_.reserve(batch_size_);
}

StageResult RecoveryFarm::recover() {
    // Check stage boundaries from previous execution and previous stage execution
    auto previous_progress{db::stages::read_stage_progress(*txn_, db::stages::kSendersKey)};
    auto bodies_stage_progress{db::stages::read_stage_progress(*txn_, db::stages::kBlockBodiesKey)};

    if (previous_progress == bodies_stage_progress) {
        // Nothing to process
        return StageResult::kSuccess;
    } else if (previous_progress > bodies_stage_progress) {
        // Something bad had happened. Not possible sender stage is ahead of bodies
        // Maybe we need to unwind ?
        log::Error() << "Bad progress sequence. Sender stage progress " << previous_progress << " while Bodies stage "
                     << bodies_stage_progress;
        return StageResult::kInvalidProgress;
    }

    auto expected_block_number = previous_progress + 1;

    // Load canonical headers
    current_phase_ = 1;
    auto stage_result{fill_canonical_headers(expected_block_number, bodies_stage_progress)};
    if (stage_result != StageResult::kSuccess) {
        return stage_result;
    }

    // Load block bodies
    uint64_t reached_block_num{0};                 // Block number being processed
    header_index_offset_ = expected_block_number;  // See collect_workers_results

    log::Trace() << "Senders begin read block bodies ... ";
    current_phase_ = 2;
    auto bodies_table{db::open_cursor(*txn_, db::table::kBlockBodies)};
    auto transactions_table{db::open_cursor(*txn_, db::table::kBlockTransactions)};

    std::vector<Transaction> transactions;

    // Set to first block and read all in sequence
    auto bodies_initial_key{db::block_key(expected_block_number, headers_it_1_->block_hash.bytes)};
    auto body_data{bodies_table.find(db::to_slice(bodies_initial_key), false)};
    while (body_data.done) {
        auto body_data_key_view{db::from_slice(body_data.key)};
        reached_block_num = endian::load_big_u64(body_data_key_view.data());
        if (reached_block_num < expected_block_number) {
            // The same block height has been recorded
            // but is not canonical;
            body_data = bodies_table.to_next(false);
            continue;
        } else if (reached_block_num > expected_block_number) {
            // We surpassed the expected block which means
            // either the db misses a block or blocks are not persisted
            // in sequence
            log::Error() << "Senders' recovery : Bad block sequence expected " << expected_block_number << " got "
                         << reached_block_num;
            stage_result = StageResult::kBadChainSequence;
            break;
        }

        if (memcmp(&body_data_key_view[8], headers_it_1_->block_hash.bytes, sizeof(kHashLength)) != 0) {
            // We stumbled into a non-canonical block (not matching header)
            // move next and repeat
            body_data = bodies_table.to_next(false);
            continue;
        }

        // Every 1024 blocks check the SignalHandler has been triggered
        if ((reached_block_num % 1024 == 0) && is_stopping()) {
            break;
        }

        // Get the body and its transactions
        auto body_rlp{db::from_slice(body_data.value)};
        auto block_body{db::detail::decode_stored_block_body(body_rlp)};
        if (block_body.txn_count) {
            headers_it_1_->txn_count = block_body.txn_count;
            db::read_transactions(transactions_table, block_body.base_txn_id, block_body.txn_count, transactions);
            stage_result = transform_and_fill_batch(reached_block_num, transactions);
            if (stage_result != StageResult::kSuccess) {
                break;
            }
        }

        // After processing move to next block number and header
        if (++headers_it_1_ == headers_.end()) {
            // We'd go beyond collected canonical headers
            break;
        }
        expected_block_number++;
        body_data = bodies_table.to_next(false);
    }

    log::Trace("Senders end", {"block", std::to_string(reached_block_num)});

    if (!is_stopping()                            // No stop requests
        && stage_result == StageResult::kSuccess  // Previous steps ok
        && dispatch_batch()                       // Residual batch dispatched
    ) {
        wait_workers_completion();
        current_phase_ = 3;

        // If everything ok from previous steps wait for all workers to complete
        // and collect results

        collect_workers_results();
        if (!collector_.empty()) {
            try {
                // Prepare target table
                auto target_table{db::open_cursor(*txn_, db::table::kSenders)};
                log::Trace() << "ETL Load : Loading data into " << db::table::kSenders.name << " "
                             << human_size(collector_.size());
                collector_.load(target_table, nullptr, MDBX_put_flags_t::MDBX_APPEND);

                // Update stage progress with last reached block number
                db::stages::write_stage_progress(*txn_, db::stages::kSendersKey, reached_block_num);
                txn_.commit();

            } catch (const mdbx::exception& ex) {
                log::Error() << "Unexpected db error in " << std::string(__FUNCTION__) << " : " << ex.what();
                stage_result = StageResult::kDbError;
            } catch (const std::exception& ex) {
                log::Error() << "Unexpected error in " << std::string(__FUNCTION__) << " : " << ex.what();
                stage_result = StageResult::kUnexpectedError;
            } catch (...) {
                log::Error() << "Unknown error in " << std::string(__FUNCTION__);
                stage_result = StageResult::kUnexpectedError;
            }
        }
    }

    stop_all_workers(/*wait=*/true);
    headers_.clear();
    workers_connections_.clear();
    workers_.clear();
    return is_stopping() ? StageResult::kAborted : stage_result;
}

StageResult RecoveryFarm::unwind(mdbx::txn& db_transaction, BlockNum new_height) {
    log::Info() << "Unwinding Senders' table to height " << new_height;
    try {
        auto unwind_table{db::open_cursor(db_transaction, db::table::kSenders)};
        auto unwind_point{db::block_key(new_height + 1)};
        db::cursor_erase(unwind_table, unwind_point);

        // Eventually update new stage height
        db::stages::write_stage_progress(db_transaction, db::stages::kSendersKey, new_height);

        return StageResult::kSuccess;

    } catch (const mdbx::exception& ex) {
        log::Error() << "Unexpected db error in " << std::string(__FUNCTION__) << " : " << ex.what();
        return StageResult::kDbError;
    } catch (...) {
        log::Error() << "Unexpected unknown error in " << std::string(__FUNCTION__);
        return StageResult::kUnexpectedError;
    }
}

std::vector<std::string> RecoveryFarm::get_log_progress() {
    if (!is_stopping()) {
        switch (current_phase_) {
            case 1:
                return {"phase", std::to_string(current_phase_) + "/3", "blocks", std::to_string(headers_.size())};
            case 2:
                return {"phase",        std::to_string(current_phase_) + "/3",  //
                        "blocks",       std::to_string(headers_.size()),        //
                        "current",      std::to_string(total_processed_blocks_),
                        "transactions", std::to_string(total_collected_transactions_),
                        "workers",      std::to_string(workers_in_flight_.load())};
            case 3:
                return {"phase", std::to_string(current_phase_) + "/3", "key", collector_.get_load_key()};
            default:
                break;
        }
    }
    return {};
}

void RecoveryFarm::stop_all_workers(bool wait) {
    for (const auto& worker : workers_) {
        log::Trace("Stopping recoverer", {"id", std::to_string(worker->get_id())});
        worker->stop(wait);
    }
}

void RecoveryFarm::wait_workers_completion() {
    while (workers_in_flight_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

std::optional<size_t> RecoveryFarm::get_harvestable_worker() {
    std::optional<size_t> ret;
    {
        std::scoped_lock lck(workers_mtx_);
        if (!harvestable_workers_.empty()) {
            ret.emplace(harvestable_workers_.front());
            harvestable_workers_.pop();
        }
    }
    return ret;
}

bool RecoveryFarm::collect_workers_results() {
    bool ret{true};
    try {
        std::vector<RecoveryPackage> worker_batch;
        auto harvestable_worker{get_harvestable_worker()};
        while (harvestable_worker.has_value()) {
            auto& worker{*(workers_.at(harvestable_worker.value()))};
            log::Trace("Collecting results", {"worker", std::to_string(harvestable_worker.value())});
            worker.set_work(worker_batch, /*kick=*/false);
            BlockNum block_num{0};
            Bytes etl_key;
            Bytes etl_data;
            for (const auto& package : worker_batch) {
                if (package.block_num != block_num) {
                    if (!etl_key.empty()) {
                        collector_.collect({etl_key, etl_data});
                        etl_key.clear();
                        etl_data.clear();
                    }
                    block_num = package.block_num;
                    const auto& header_info{headers_.at(block_num - header_index_offset_)};
                    etl_key = db::block_key(block_num, header_info.block_hash.bytes);
                    etl_data.clear();
                }
                etl_data.append(package.tx_from.bytes, sizeof(evmc::address));
            }
            if (!etl_key.empty()) {
                collector_.collect({etl_key, etl_data});
                etl_key.clear();
                etl_data.clear();
            }
            worker_batch.clear();
            harvestable_worker = get_harvestable_worker();
        }

    } catch (const std::exception& ex) {
        log::Error() << "Unexpected error in " << std::string(__FUNCTION__) << " : " << ex.what();
        ret = false;
    }

    // Something bad happened stop all recovery process
    if (!ret) {
        stop();
    }
    return ret;
}

StageResult RecoveryFarm::transform_and_fill_batch(uint64_t block_num, const std::vector<Transaction>& transactions) {
    if (is_stopping()) {
        return StageResult::kAborted;
    }

    const evmc_revision rev{node_settings_->chain_config->revision(block_num)};
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
                    log::Error() << "Transaction type " << magic_enum::enum_name<Transaction::Type>(transaction.type)
                                 << " for transaction #" << tx_id << " in block #" << block_num << " before Berlin";
                    return StageResult::kInvalidTransaction;
                }
                break;
            case Transaction::Type::kEip1559:
                if (!has_london) {
                    log::Error() << "Transaction type " << magic_enum::enum_name<Transaction::Type>(transaction.type)
                                 << " for transaction #" << tx_id << " in block #" << block_num << " before London";
                    return StageResult::kInvalidTransaction;
                }
                break;
        }

        if (!silkworm::ecdsa::is_valid_signature(transaction.r, transaction.s, has_homestead)) {
            log::Error() << "Got invalid signature for transaction #" << tx_id << " in block #" << block_num;
            return StageResult::kInvalidTransaction;
        }

        if (transaction.chain_id.has_value()) {
            if (!has_spurious_dragon) {
                log::Error() << "EIP-155 signature for transaction #" << tx_id << " in block #" << block_num
                             << " before Spurious Dragon";
                return StageResult::kInvalidTransaction;
            } else if (transaction.chain_id.value() != node_settings_->chain_config->chain_id) {
                log::Error() << "EIP-155 invalid signature for transaction #" << tx_id << " in block #" << block_num;
                return StageResult::kInvalidTransaction;
            }
        }

        Bytes rlp{};
        rlp::encode(rlp, transaction, /*for_signing=*/true, /*wrap_eip2718_into_array=*/false);

        auto tx_hash{keccak256(rlp)};
        batch_.push_back(RecoveryPackage{block_num, tx_hash, transaction.odd_y_parity});
        intx::be::unsafe::store(batch_.back().tx_signature, transaction.r);
        intx::be::unsafe::store(batch_.back().tx_signature + kHashLength, transaction.s);

        ++tx_id;
    }
    total_processed_blocks_++;

    // Do we overflow ?
    if (batch_.size() > batch_size_) {
        total_collected_transactions_ += batch_.size();
        if (!dispatch_batch()) {
            return StageResult::kUnexpectedError;
        }
    }

    return is_stopping() ? StageResult::kAborted : StageResult::kSuccess;
}

bool RecoveryFarm::dispatch_batch() {
    // Locate first available worker
    uint_fast32_t wait_count{5};
    while (!is_stopping() && collect_workers_results() == true) {
        auto it = as_range::find_if(workers_, [](const std::unique_ptr<RecoveryWorker>& w) {
            return w->get_state() == RecoveryWorker::State::kKickWaiting;
        });

        if (it != workers_.end()) {
            log::Trace("Dispatching batch ...",
                       {"worker", std::to_string((*it)->get_id()), "items", std::to_string(batch_.size())});
            (*it)->set_work(batch_, /*kick=*/true);  // Worker will swap contents
            workers_in_flight_++;
            batch_.clear();
            batch_.reserve(batch_size_);
            return true;
        }

        // We don't have a worker available
        // Maybe we can create a new one if available
        if (workers_.size() != max_workers_) {
            if (initialize_new_worker()) {
                continue;
            }
            if (workers_.empty()) {
                log::Error() << "Unable to initialize any recovery worker. Aborting";
                return false;
            }
            log::Debug() << "Max recovery workers adjusted " << max_workers_ << " -> " << workers_.size();
            max_workers_ = static_cast<uint32_t>(workers_.size());  // Don't try to spawn new workers. Maybe we're OOM
        }

        // No other option than wait a while and retry
        if (!--wait_count) {
            wait_count = 5;
            log::Info() << "Waiting for available worker ...";
        }
        std::unique_lock lck(workers_mtx_);
        (void)worker_completed_cv_.wait_for(lck, std::chrono::seconds(5));
    }

    return is_stopping();
}

bool RecoveryFarm::initialize_new_worker() {
    if (is_stopping()) {
        return false;
    }
    log::Trace("Spawning new Recovery worker", {"id", std::to_string(workers_.size())});
    using namespace std::placeholders;
    try {
        workers_.emplace_back(new RecoveryWorker(workers_.size()));
        workers_connections_.emplace_back(
            workers_.back()->signal_task_completed.connect(std::bind(&RecoveryFarm::task_completed_handler, this, _1)));
        workers_connections_.emplace_back(workers_.back()->signal_worker_stopped.connect(
            std::bind(&RecoveryFarm::worker_completed_handler, this, _1)));
        workers_.back()->start(/*wait=*/true);
        return true;
    } catch (const std::exception& ex) {
        log::Error() << "Unable to initialize new recovery worker : " << ex.what();
        return false;
    }
}

StageResult RecoveryFarm::fill_canonical_headers(BlockNum from, BlockNum to) noexcept {
    uint64_t headers_count{to - from};
    headers_.reserve(headers_count);
    if (headers_count > 16) {
        log::Info("Collecting headers ...", {"from", std::to_string(from), "to", std::to_string(to)});
    }

    // Locate starting canonical header selected
    BlockNum reached_block_num{0};
    BlockNum expected_block_num{from};

    // Enclose in try catch block as db cursor reads may fail
    try {
        auto hashes_table{db::open_cursor(*txn_, db::table::kCanonicalHashes)};
        auto header_key{db::block_key(expected_block_num)};
        // Read all headers up to upper bound (included)
        auto data{hashes_table.find(db::to_slice(header_key), false)};
        while (data.done) {
            reached_block_num = endian::load_big_u64(static_cast<uint8_t*>(data.key.data()));
            SILKWORM_ASSERT(reached_block_num == expected_block_num);
            SILKWORM_ASSERT(data.value.length() == kHashLength);

            // We have a canonical header hash in right sequence
            headers_.emplace_back(0, to_bytes32(db::from_slice(data.value)));
            if (reached_block_num == to) {
                break;
            }
            expected_block_num++;
            data = hashes_table.to_next(false);

            // Do we need to abort ?
            if ((expected_block_num % 1024 == 0) && is_stopping()) {
                return StageResult::kAborted;
            }
        }

        // If we've not reached block_to something is wrong
        if (reached_block_num != to) {
            log::Error() << "Should have reached block " << to << " got " << reached_block_num;
            return StageResult::kBadChainSequence;
        }

        // Initialize iterators
        headers_it_1_ = headers_.begin();
        return is_stopping() ? StageResult::kAborted : StageResult::kSuccess;

    } catch (const mdbx::exception& ex) {
        log::Error() << "Unexpected database error in " << std::string(__FUNCTION__) << " : " << ex.what();
        return StageResult::kDbError;
    } catch (const std::exception& ex) {
        log::Error() << "Unexpected error in " << std::string(__FUNCTION__) << " : " << ex.what();
        return StageResult::kUnexpectedError;
    } catch (...) {
        log::Error() << "Unexpected error in " << std::string(__FUNCTION__) << " : unknown error";
        return StageResult::kUnexpectedError;
    }
}

void RecoveryFarm::task_completed_handler(RecoveryWorker* sender) {

    std::scoped_lock lck(workers_mtx_);
    harvestable_workers_.push(sender->get_id());
    if (workers_in_flight_) {
        workers_in_flight_--;
    }
    worker_completed_cv_.notify_one();
}

void RecoveryFarm::worker_completed_handler(Worker* sender) {

    std::scoped_lock lck(workers_mtx_);
    if (workers_in_flight_) {
        workers_in_flight_--;
    }
    if (sender->has_exception()) {
        stop();
    }
    worker_completed_cv_.notify_one();
}

}  // namespace silkworm::stagedsync::recovery
