/*
   Copyright 2020-2021 The Silkworm Authors

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

#include <boost/format.hpp>

#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>

namespace silkworm::stagedsync::recovery {

RecoveryFarm::RecoveryFarm(mdbx::txn& db_transaction, uint32_t max_workers, size_t max_batch_size,
                           etl::Collector& collector)
    : db_transaction_{db_transaction},
      max_workers_{max_workers},
      max_batch_size_{max_batch_size},
      collector_{collector} {
    workers_.reserve(max_workers);
    batch_.reserve(max_batch_size);
}

RecoveryFarm::~RecoveryFarm() {
    while (!workers_.empty()) {
        workers_.back().second.disconnect();
        workers_.pop_back();
    }
}

StageResult RecoveryFarm::recover(BlockNum to) {
    // Check we have a valid chain configuration
    auto chain_config{db::read_chain_config(db_transaction_)};
    if (!chain_config.has_value()) {
        return StageResult::kUnknownChainId;
    }

    // Check stage boundaries from previous execution and previous stage execution
    BlockNum from{0};
    {
        auto senders_stage_progress{db::stages::read_stage_progress(db_transaction_, db::stages::kSendersKey)};
        auto bodies_stage_progress{db::stages::read_stage_progress(db_transaction_, db::stages::kBlockBodiesKey)};
        if (senders_stage_progress > bodies_stage_progress) {
            // Something bad had happened. Not possible sender stage is ahead of bodies
            // Maybe we need to unwind ?
            SILKWORM_LOG(LogLevel::Error) << "Bad progress sequence. Sender stage progress " << senders_stage_progress
                                          << " while Bodies stage " << bodies_stage_progress << std::endl;
            return StageResult::kInvalidProgress;
        }
        to = std::min(bodies_stage_progress, to);
        if (to <= senders_stage_progress) {
            return StageResult::kSuccess;  // Really nothing to process
        }
        from = senders_stage_progress + 1;
    }

    // Load canonical headers
    uint64_t headers_count{to - from};
    headers_.reserve(headers_count);
    auto stage_result{fill_canonical_headers(from, to)};
    if (stage_result != StageResult::kSuccess) {
        return stage_result;
    }

    if (headers_.size() > 16) {
        SILKWORM_LOG(LogLevel::Info) << "Collected " << headers_.size() << " canonical headers" << std::endl;
    }

    // Load block bodies
    uint64_t reached_block_num{0};      // Block number being processed
    uint64_t expected_block_num{from};  // Expected block number in sequence
    header_index_offset_ = from;        // See collect_workers_results

    SILKWORM_LOG(LogLevel::Trace) << "Begin read block bodies ... " << std::endl;
    auto bodies_table{db::open_cursor(db_transaction_, db::table::kBlockBodies)};
    auto transactions_table{db::open_cursor(db_transaction_, db::table::kEthTx)};

    // Set to first block and read all in sequence
    auto bodies_initial_key{db::block_key(expected_block_num, headers_it_1_->bytes)};
    auto body_data{bodies_table.find(db::to_slice(bodies_initial_key), false)};
    while (body_data.done && !should_stop()) {
        auto body_data_key_view{db::from_slice(body_data.key)};
        reached_block_num = endian::load_big_u64(body_data_key_view.data());
        if (reached_block_num < expected_block_num) {
            // The same block height has been recorded
            // but is not canonical;
            body_data = bodies_table.to_next(false);
            continue;
        } else if (reached_block_num > expected_block_num) {
            // We surpassed the expected block which means
            // either the db misses a block or blocks are not persisted
            // in sequence
            SILKWORM_LOG(LogLevel::Error) << "Senders' recovery : Bad block sequence expected " << expected_block_num
                                          << " got " << reached_block_num << std::endl;
            stage_result = StageResult::kBadChainSequence;
            break;
        }

        if (memcmp(&body_data_key_view[8], headers_it_1_->bytes, sizeof(kHashLength)) != 0) {
            // We stumbled into a non-canonical block (not matching header)
            // move next and repeat
            body_data = bodies_table.to_next(false);
            continue;
        }

        // Get the body and its transactions
        auto body_rlp{db::from_slice(body_data.value)};
        auto block_body{db::detail::decode_stored_block_body(body_rlp)};
        if (block_body.txn_count) {
            std::vector<Transaction> transactions{
                db::read_transactions(transactions_table, block_body.base_txn_id, block_body.txn_count)};
            stage_result = transform_and_fill_batch(chain_config.value(), reached_block_num, transactions);
            if (stage_result != StageResult::kSuccess) {
                break;
            }
        }

        // After processing move to next block number and header
        if (++headers_it_1_ == headers_.end()) {
            // We'd go beyond collected canonical headers
            break;
        }
        expected_block_num++;
        body_data = bodies_table.to_next(false);
    }

    if (!should_stop()                            // No stop requests
        && stage_result == StageResult::kSuccess  // Previous steps ok
        && dispatch_batch()                       // Residual batch dispatched
    ) {
        SILKWORM_LOG(LogLevel::Trace) << "End   read block bodies ... " << std::endl;
        wait_workers_completion();

        // If everything ok from previous steps wait for all workers to complete
        // and collect results

        collect_workers_results();
        if (!collector_.empty() && !should_stop()) {
            try {
                // Prepare target table
                auto target_table{db::open_cursor(db_transaction_, db::table::kSenders)};
                SILKWORM_LOG(LogLevel::Info)
                    << "ETL Load [2/2] : Loading data into " << db::table::kSenders.name << std::endl;
                collector_.load(target_table, nullptr, MDBX_put_flags_t::MDBX_APPEND,
                                /* log_every_percent = */ (total_recovered_transactions_ <= max_batch_size_ ? 50 : 10));

                // Update stage progress with last reached block number
                db::stages::write_stage_progress(db_transaction_, db::stages::kSendersKey, reached_block_num);

            } catch (const mdbx::exception& ex) {
                SILKWORM_LOG(LogLevel::Error)
                    << "Unexpected db error in " << std::string(__FUNCTION__) << " : " << ex.what() << std::endl;
                stage_result = StageResult::kDbError;
            } catch (const std::exception& ex) {
                SILKWORM_LOG(LogLevel::Error)
                    << "Unexpected error in " << std::string(__FUNCTION__) << " : " << ex.what() << std::endl;
                stage_result = StageResult::kUnexpectedError;
            } catch (...) {
                SILKWORM_LOG(LogLevel::Error) << "Unknown error in " << std::string(__FUNCTION__) << std::endl;
                stage_result = StageResult::kUnexpectedError;
            }
        }
    }

    stop_all_workers(/*wait=*/true);
    return stage_result;
}

StageResult RecoveryFarm::unwind(mdbx::txn& db_transaction, BlockNum new_height) {
    SILKWORM_LOG(LogLevel::Info) << "Unwinding Senders' table to height " << new_height << std::endl;
    try {
        auto unwind_table{db::open_cursor(db_transaction, db::table::kSenders)};
        auto unwind_point{db::block_key(new_height + 1)};
        db::cursor_erase(unwind_table, unwind_point);

        // Eventually update new stage height
        db::stages::write_stage_progress(db_transaction, db::stages::kSendersKey, new_height);

        return StageResult::kSuccess;

    } catch (const mdbx::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << "Unexpected db error in " << std::string(__FUNCTION__) << " : " << ex.what()
                                      << std::endl;
        return StageResult::kDbError;
    } catch (...) {
        SILKWORM_LOG(LogLevel::Error) << "Unexpected unknown error in " << std::string(__FUNCTION__) << std::endl;
        return StageResult::kUnexpectedError;
    }
}

void RecoveryFarm::stop_all_workers(bool wait) {
    SILKWORM_LOG(LogLevel::Debug) << "Stopping workers ... " << std::endl;
    for (const auto& item : workers_) {
        item.first->stop(wait);
    }
}

void RecoveryFarm::wait_workers_completion() {
    if (!workers_.empty()) {
        uint32_t attempts{0};
        do {
            auto it = std::find_if(workers_.begin(), workers_.end(), [](const worker_pair& w) {
                return w.first->get_status() == RecoveryWorker::Status::Working;
            });
            if (it == workers_.end()) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            if (!(++attempts % 60)) {
                SILKWORM_LOG(LogLevel::Info) << "Waiting for workers to complete ..." << std::endl;
            }
        } while (true);
    }
}

bool RecoveryFarm::collect_workers_results() {
    static std::string fmt_row{"%10u b %12u t %4u w"};

    bool ret{true};
    std::vector<std::pair<BlockNum, ByteView>> worker_results{};
    while (ret) {
        // Check we have results to pull
        std::unique_lock l(harvest_mutex_);
        if (harvest_pairs_.empty()) {
            break;
        }

        // Select worker and pop the queue
        auto& worker{workers_.at(harvest_pairs_.front().first)};
        SILKWORM_LOG(LogLevel::Trace) << "Collecting  results from worker " << worker.first->get_id() << std::endl;
        harvest_pairs_.pop();
        l.unlock();

        auto status = worker.first->get_status();
        switch (status) {
            case RecoveryWorker::Status::Error:
                SILKWORM_LOG(LogLevel::Error) << "Got error from worker #" << worker.first->get_id() << " : "
                                              << worker.first->get_error() << std::endl;
                ret = false;
                break;
            case RecoveryWorker::Status::Aborted:
                SILKWORM_LOG(LogLevel::Trace) << "Got aborted from worker #" << worker.first->get_id() << std::endl;
                ret = false;
                break;
            case RecoveryWorker::Status::ResultsReady:
                SILKWORM_LOG(LogLevel::Trace)
                    << "Collecting results from worker #" << worker.first->get_id() << std::endl;
                if (worker.first->pull_results(worker_results)) {
                    try {
                        for (const auto& [block_num, data] : worker_results) {
                            total_processed_blocks_++;
                            total_recovered_transactions_ += (data.length() / kAddressLength);
                            auto etl_key{db::block_key(block_num, headers_.at(block_num - header_index_offset_).bytes)};
                            Bytes etl_data(data.data(), data.length());
                            collector_.collect(etl::Entry{etl_key, etl_data});
                        }
                        SILKWORM_LOG(LogLevel::Info) << "ETL Load [1/2] : "
                                                     << (boost::format(fmt_row) % worker_results.back().first %
                                                         total_recovered_transactions_ % workers_in_flight_.load())
                                                     << std::endl;
                        worker_results.resize(0);

                    } catch (const std::exception& ex) {
                        SILKWORM_LOG(LogLevel::Error)
                            << "Unexpected error in " << std::string(__FUNCTION__) << " : " << ex.what() << std::endl;
                        ret = false;
                    }
                } else {
                    SILKWORM_LOG(LogLevel::Error)
                        << "Unexpected error in " << std::string(__FUNCTION__) << " : "
                        << "could not pull results from worker #" << worker.first->get_id() << std::endl;
                    ret = false;
                }
                break;

            default:
                // Should not happen
                SILKWORM_LOG(LogLevel::Error) << "Got not ready status for harvest worker " << std::endl;
                ret = false;
        }
    }

    // Something bad happened stop all recovery process
    if (!ret) {
        stop();
    }
    return ret;
}

StageResult RecoveryFarm::transform_and_fill_batch(const ChainConfig& config, uint64_t block_num,
                                                   std::vector<Transaction>& transactions) {
    if (transactions.empty()) {
        return StageResult::kSuccess;
    }

    // Do we overflow ?
    if ((batch_.size() + transactions.size()) > max_batch_size_) {
        if (!dispatch_batch()) {
            return StageResult::kUnexpectedError;
        }
    }

    const evmc_revision rev{config.revision(block_num)};
    const bool has_homestead{rev >= EVMC_HOMESTEAD};
    const bool has_spurious_dragon{rev >= EVMC_SPURIOUS_DRAGON};
    const bool has_berlin{rev >= EVMC_BERLIN};
    const bool has_london{rev >= EVMC_LONDON};

    uint32_t tx_id{0};
    for (const auto& transaction : transactions) {

        switch (transaction.type) {
            case Transaction::Type::kEip2930:
                if (!has_berlin) {
                    SILKWORM_LOG(LogLevel::Error) << "Non legacy transaction type for transaction #" << tx_id << " in block #"
                                          << block_num << " before Berlin" << std::endl;
                    return StageResult::kInvalidTransaction;
                }
            case Transaction::Type::kEip1559:
                if (!has_london) {
                    SILKWORM_LOG(LogLevel::Error) << "Non legacy transaction type for transaction #" << tx_id << " in block #"
                                          << block_num << " before London" << std::endl;
                    return StageResult::kInvalidTransaction;
                }
        }

        if (!silkworm::ecdsa::is_valid_signature(transaction.r, transaction.s, has_homestead)) {
            SILKWORM_LOG(LogLevel::Error)
                << "Got invalid signature for transaction #" << tx_id << " in block #" << block_num << std::endl;
            return StageResult::kInvalidTransaction;
        }

        if (transaction.chain_id.has_value()) {
            if (!has_spurious_dragon) {
                SILKWORM_LOG(LogLevel::Error) << "EIP-155 signature for transaction #" << tx_id << " in block #"
                                              << block_num << " before Spurious Dragon" << std::endl;
                return StageResult::kInvalidTransaction;
            } else if (transaction.chain_id.value() != config.chain_id) {
                SILKWORM_LOG(LogLevel::Error) << "EIP-155 invalid signature for transaction #" << tx_id << " in block #"
                                              << block_num << std::endl;
                return StageResult::kInvalidTransaction;
            }
        }

        Bytes rlp{};
        rlp::encode(rlp, transaction, /*for_signing=*/true, /*wrap_eip2718_into_array=*/false);

        auto hash{keccak256(rlp)};
        batch_.push_back(RecoveryPackage{block_num, hash, transaction.odd_y_parity});
        intx::be::unsafe::store(batch_.back().signature, transaction.r);
        intx::be::unsafe::store(batch_.back().signature + kHashLength, transaction.s);

        tx_id++;
    }

    return StageResult::kSuccess;
}

bool RecoveryFarm::dispatch_batch() {
    if (should_stop() || batch_.empty()) {
        return true;
    }

    // First worker created
    if (workers_.empty()) {
        if (!initialize_new_worker()) {
            return false;
        }
    }

    // Locate first available worker
    while (!should_stop()) {
        auto it = std::find_if(workers_.begin(), workers_.end(), [](const worker_pair& w) {
            return w.first->get_status() == RecoveryWorker::Status::Idle;
        });

        if (it != workers_.end()) {
            SILKWORM_LOG(LogLevel::Trace) << "Dispatching package to worker #" << it->first->get_id() << std::endl;
            it->first->set_work(batch_id_++, batch_);  // Worker will swap contents
            batch_.resize(0);
            workers_in_flight_++;
            return true;
        } else {
            // Do we have ready results from workers that we need to harvest ?
            it = std::find_if(workers_.begin(), workers_.end(), [](const worker_pair& w) {
                auto s = static_cast<int>(w.first->get_status());
                return (s >= 2);
            });
            if (it != workers_.end()) {
                if (!collect_workers_results()) {
                    return false;
                }
                continue;
            }

            // We don't have a worker available
            // Maybe we can create a new one if available
            if (workers_.size() != max_workers_) {
                if (initialize_new_worker()) {
                    continue;
                }
                SILKWORM_LOG(LogLevel::Info)
                    << "Max recovery workers adjusted " << max_workers_ << " -> " << workers_.size() << std::endl;
                max_workers_ = workers_.size();  // Don't try to spawn new workers. Maybe we're OOM
            }

            // No other option than wait a while and retry
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    return false;
}

bool RecoveryFarm::initialize_new_worker() {
    SILKWORM_LOG(LogLevel::Trace) << "Launching worker #" << workers_.size() << std::endl;
    try {
        auto worker{std::make_unique<RecoveryWorker>(workers_.size(), max_batch_size_ * kAddressLength)};
        auto connector{
            worker->signal_completed.connect(boost::bind(&RecoveryFarm::worker_completed_handler, this, _1))};
        workers_.emplace_back(std::move(worker), std::move(connector));
        workers_.back().first->start(/*wait=*/true);
        return workers_.back().first->get_state() == Worker::WorkerState::kStarted;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << "Unable to initialize new recovery worker : " << ex.what() << std::endl;
        return false;
    }
}

StageResult RecoveryFarm::fill_canonical_headers(BlockNum from, BlockNum to) noexcept {
    if ((to - from) > 16) {
        SILKWORM_LOG(LogLevel::Info) << "Loading canonical headers [" << from << " .. " << to << "]" << std::endl;
    }

    // Locate starting canonical header selected
    BlockNum reached_block_num{0};
    BlockNum expected_block_num{from};

    // Enclose in try catch block as db cursor reads may fail
    try {
        auto hashes_table{db::open_cursor(db_transaction_, db::table::kCanonicalHashes)};
        auto header_key{db::block_key(expected_block_num)};
        // Read all headers up to upper bound (included)
        auto data{hashes_table.find(db::to_slice(header_key), false)};
        while (data.done) {
            reached_block_num = endian::load_big_u64(static_cast<uint8_t*>(data.key.iov_base));
            if (reached_block_num != expected_block_num) {
                SILKWORM_LOG(LogLevel::Error) << "Bad block number sequence ! Expected " << expected_block_num << " got "
                                              << reached_block_num << std::endl;
                return StageResult::kBadChainSequence;
            }

            if (data.value.length() != kHashLength) {
                SILKWORM_LOG(LogLevel::Error)
                    << "Bad header hash at height " << reached_block_num << " (hash len == " << data.value.length()
                    << " - should be " << kHashLength << ")" << std::endl;
                return StageResult::kBadBlockHash;
            }

            // We have a canonical header hash in right sequence
            headers_.push_back(to_bytes32(db::from_slice(data.value)));
            if (reached_block_num == to) {
                break;
            }
            expected_block_num++;
            data = hashes_table.to_next(false);
        }

        // If we've not reached block_to something is wrong
        if (reached_block_num != to) {
            SILKWORM_LOG(LogLevel::Error)
                << "Should have reached block " << to << " got " << reached_block_num << std::endl;
            return StageResult::kBadChainSequence;
        }

        // Initialize iterators
        headers_it_1_ = headers_.begin();
        return StageResult::kSuccess;

    } catch (const mdbx::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << "Unexpected database error in " << std::string(__FUNCTION__) << " : "
                                      << ex.what() << std::endl;
        return StageResult::kDbError;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << "Unexpected error in " << std::string(__FUNCTION__) << " : " << ex.what()
                                      << std::endl;
        return StageResult::kUnexpectedError;
    } catch (...) {
        SILKWORM_LOG(LogLevel::Error) << "Unexpected error in " << std::string(__FUNCTION__) << " : unknown error"
                                      << std::endl;
        return StageResult::kUnexpectedError;
    }
}

void RecoveryFarm::worker_completed_handler(RecoveryWorker* sender) {
    // Ensure worker threads complete batches in the same order they
    // were launched
    while (completed_batch_id_.load() != sender->get_batch_id()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Save the id of worker ready for harvest
    std::lock_guard l(harvest_mutex_);
    harvest_pair item{sender->get_id(), sender->get_batch_id()};
    harvest_pairs_.push(item);
    completed_batch_id_++;
    workers_in_flight_--;
}

}  // namespace silkworm::stagedsync::recovery
