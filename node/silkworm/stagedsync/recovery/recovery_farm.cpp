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

namespace silkworm::stagedsync::recovery {

RecoveryFarm::RecoveryFarm(mdbx::txn& db_transaction, uint32_t max_workers, size_t max_batch_size,
                           etl::Collector& collector)
    : db_transaction_{db_transaction},
      max_workers_{max_workers},
      max_batch_size_{max_batch_size},
      collector_{collector} {
    workers_.reserve(max_workers);
}

StageResult RecoveryFarm::recover(uint64_t height_from, uint64_t height_to) {
    auto ret{StageResult::kSuccess};

    auto config{db::read_chain_config(db_transaction_)};
    if (!config.has_value()) {
        throw std::runtime_error("Invalid Chain Config.");
    }

    // Retrieve previous stage height
    auto senders_stage_height{db::stages::get_stage_progress(db_transaction_, db::stages::kSendersKey)};
    if (height_from > (senders_stage_height + 1)) {
        height_from = (senders_stage_height + 1);
    }
    if (height_from <= senders_stage_height) {
        height_from = senders_stage_height + 1;
    }

    auto blocks_stage_height{db::stages::get_stage_progress(db_transaction_, db::stages::kBlockBodiesKey)};
    if (height_to > blocks_stage_height) {
        height_to = blocks_stage_height;
        if (height_to < height_from) {
            // We actually don't need to recover anything
            return StageResult::kSuccess;
        }
    }

    if (height_from > height_to) {
        return StageResult::kInvalidRange;
    }

    // Load canonical headers
    auto ret_status{StageResult::kSuccess};
    uint64_t headers_count{height_to - height_from + 1};
    headers_.reserve(headers_count);
    ret_status = fill_canonical_headers(height_from, height_to);
    if (ret_status != StageResult::kSuccess) {
        return ret_status;
    }

    SILKWORM_LOG(LogLevel::Info) << "Collected " << headers_.size() << " canonical headers" << std::endl;
    if (headers_.size() != headers_count) {
        SILKWORM_LOG(LogLevel::Error) << "A total of " << headers_count << " was expected" << std::endl;
        return StageResult::kBadChainSequence;
    }

    headers_it_1_ = headers_.begin();
    headers_it_2_ = headers_.begin();

    // Load block bodies
    uint64_t block_num{0};                     // Block number being processed
    uint64_t expected_block_num{height_from};  // Expected block number in sequence

    SILKWORM_LOG(LogLevel::Debug) << "Begin read block bodies ... " << std::endl;
    auto bodies_table{db::open_cursor(db_transaction_, db::table::kBlockBodies)};
    auto transactions_table{db::open_cursor(db_transaction_, db::table::kEthTx)};

    // Set to first block and read all in sequence
    auto block_key{db::block_key(expected_block_num, headers_it_1_->bytes)};
    if (!bodies_table.seek(db::to_slice(block_key))) {
        return StageResult::kBadChainSequence;
    }

    // Initializes first batch
    init_batch();
    auto block_data{bodies_table.current()};
    while (block_data && !should_stop()) {
        auto key_view{db::from_slice(block_data.key)};
        block_num = boost::endian::load_big_u64(static_cast<uint8_t*>(block_data.key.iov_base));
        if (block_num < expected_block_num) {
            // The same block height has been recorded
            // but is not canonical;
            block_data = bodies_table.to_next(false);
            continue;
        } else if (block_num > expected_block_num) {
            // We surpassed the expected block which means
            // either the db misses a block or blocks are not persisted
            // in sequence
            SILKWORM_LOG(LogLevel::Error) << "Senders' recovery : Bad block sequence expected " << expected_block_num
                                          << " got " << block_num << std::endl;
            return StageResult::kBadChainSequence;
        }

        if (memcmp(&key_view[8], headers_it_1_->bytes, 32) != 0) {
            // We stumbled into a non canonical block (not matching header)
            // move next and repeat
            block_data = bodies_table.to_next(false);
            continue;
        }

        // Get the body and its transactions
        auto body_rlp{db::from_slice(block_data.value)};
        auto block_body{db::detail::decode_stored_block_body(body_rlp)};
        std::vector<Transaction> transactions{
            db::read_transactions(transactions_table, block_body.base_txn_id, block_body.txn_count)};

        if (transactions.size()) {
            if (((*batch_).size() + transactions.size()) > max_batch_size_) {
                dispatch_batch(true);
            }

            fill_batch(*config, block_num, transactions);
        }

        // After processing move to next block number and header
        if (++headers_it_1_ == headers_.end()) {
            // We'd go beyond collected canonical headers
            break;
        }

        expected_block_num++;
        block_data = bodies_table.to_next(false);
    }

    dispatch_batch(false);
    SILKWORM_LOG(LogLevel::Debug) << "End   read block bodies ... " << std::endl;

    // If everything ok from previous steps wait for all workers to complete
    // and bufferize results
    wait_workers_completion();
    if (!static_cast<int>(ret)) {
        bufferize_workers_results();
        if (collector_.size() && !should_stop()) {
            // Prepare target table
            auto target_table{db::open_cursor(db_transaction_, db::table::kSenders)};
            SILKWORM_LOG(LogLevel::Info) << "ETL Load [2/2] : Loading data into " << db::table::kSenders.name
                                         << std::endl;
            collector_.load(target_table, nullptr, MDBX_put_flags_t::MDBX_APPEND,
                            /* log_every_percent = */ (total_recovered_transactions_ <= max_batch_size_ ? 50 : 10));

            // Get the last processed block and update stage height
            auto last_processed_block{
                boost::endian::load_big_u64(static_cast<uint8_t*>(target_table.to_last().key.iov_base))};
            db::stages::set_stage_progress(db_transaction_, db::stages::kSendersKey, last_processed_block);
        }
    }

    stop_all_workers(/*wait=*/true);
    return ret;
}

StageResult RecoveryFarm::unwind(uint64_t new_height) {
    SILKWORM_LOG(LogLevel::Info) << "Unwinding Senders' table to height " << new_height << std::endl;
    auto ret{StageResult::kSuccess};
    auto unwind_table{db::open_cursor(db_transaction_, db::table::kSenders)};
    size_t rcount{db_transaction_.get_map_stat(unwind_table.map()).ms_entries};
    if (rcount) {
        if (new_height <= 1) {
            db_transaction_.clear_map(unwind_table.map());
        } else {
            Bytes key(40, '\0');
            boost::endian::store_big_u64(&key[0], new_height + 1);  // New stage height is last processed
            if (unwind_table.seek(db::to_slice(key))) {
                unwind_table.erase();
                while (unwind_table.to_next(false)) {
                    unwind_table.erase();
                    if (--rcount % 1'000 && should_stop()) {
                        ret = StageResult::kAborted;
                        break;
                    }
                }
            }
        }
    }

    // Eventually update new stage height
    if (ret == StageResult::kSuccess) {
        db::stages::set_stage_progress(db_transaction_, db::stages::kSendersKey, new_height);
    }
    return ret;
}

void RecoveryFarm::stop_all_workers(bool wait) {
    SILKWORM_LOG(LogLevel::Debug) << "Stopping workers ... " << std::endl;
    for (const auto& worker : workers_) {
        worker->stop(wait);
    }
}

void RecoveryFarm::wait_workers_completion() {
    if (workers_.size()) {
        uint64_t attempts{0};
        do {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            auto it = std::find_if(workers_.begin(), workers_.end(), [](const std::unique_ptr<RecoveryWorker>& w) {
                return w->get_status() == RecoveryWorker::Status::Working;
            });
            if (it == workers_.end()) {
                break;
            }
            if (!(++attempts % 60)) {
                SILKWORM_LOG(LogLevel::Info) << "Waiting for workers to complete" << std::endl;
            }
        } while (true);
    }
}

bool RecoveryFarm::bufferize_workers_results() {
    bool success{true};
    static std::string fmt_row{"%10u b %12u t"};

    std::vector<std::pair<uint64_t, iovec>> worker_results{};
    do {
        // Check we have results to pull
        std::unique_lock l(batches_completed_mtx);
        if (batches_completed.empty()) {
            break;
        }

        // Pull results
        auto& item{batches_completed.front()};
        auto& worker{workers_.at(item.first)};

        SILKWORM_LOG(LogLevel::Debug) << "Collecting  package " << item.second << " worker " << item.first << std::endl;

        batches_completed.pop();
        l.unlock();

        auto status = worker->get_status();
        if (status == RecoveryWorker::Status::Error) {
            SILKWORM_LOG(LogLevel::Error)
                << "Got error from worker id " << worker->get_id() << " : " << worker->get_error() << std::endl;
            success = false;
            break;
        } else if (status == RecoveryWorker::Status::Aborted) {
            success = false;
            break;
        } else if (status == RecoveryWorker::Status::ResultsReady) {
            if (!worker->pull_results(status, worker_results)) {
                success = false;
                break;
            } else {
                for (auto& [block_num, data] : worker_results) {
                    total_processed_blocks_++;
                    total_recovered_transactions_ += (data.iov_len / kAddressLength);

                    auto etl_key{db::block_key(block_num, headers_it_2_->bytes)};
                    Bytes etl_data(db::from_slice(data));
                    etl::Entry entry{etl_key, etl_data};
                    collector_.collect(entry);  // TODO check for errors (eg. disk full)
                    headers_it_2_++;
                }
                SILKWORM_LOG(LogLevel::Info)
                    << "ETL Load [1/2] : "
                    << (boost::format(fmt_row) % total_processed_blocks_ % total_recovered_transactions_) << std::endl;
            }
        }

        worker_results.clear();

    } while (!should_stop());

    if (!success) {
        should_stop_.store(true);
    }

    return success;
}

void RecoveryFarm::fill_batch(ChainConfig config, uint64_t block_num, std::vector<Transaction>& transactions) {
    const evmc_revision rev{config.revision(block_num)};
    const bool has_homestead{rev >= EVMC_HOMESTEAD};
    const bool has_spurious_dragon{rev >= EVMC_SPURIOUS_DRAGON};

    for (const auto& transaction : transactions) {
        if (!silkworm::ecdsa::is_valid_signature(transaction.r, transaction.s, has_homestead)) {
            throw std::runtime_error("Got invalid signature in transaction for block " + std::to_string(block_num));
        }

        if (transaction.chain_id) {
            if (!has_spurious_dragon) {
                throw std::runtime_error("EIP-155 signature in transaction before Spurious Dragon for block " +
                                         std::to_string(block_num));
            } else if (*transaction.chain_id != config.chain_id) {
                throw std::runtime_error("EIP-155 invalid signature in transaction for block " +
                                         std::to_string(block_num));
            }
        }

        Bytes rlp{};
        rlp::encode(rlp, transaction, /*for_signing=*/true, /*wrap_eip2718_into_array=*/false);

        auto hash{keccak256(rlp)};
        RecoveryWorker::package package{block_num, hash, transaction.odd_y_parity};
        intx::be::unsafe::store(package.signature, transaction.r);
        intx::be::unsafe::store(package.signature + 32, transaction.s);
        (*batch_).push_back(package);
    }
}

void RecoveryFarm::dispatch_batch(bool renew) {
    bool did_fail{false};
    if (should_stop()) {
        init_batch();  // Empties the batch
        throw std::runtime_error("Unable to dispatch work");
    } else if (!batch_ || !(*batch_).size()) {
        return;
    }

    // First worker created
    if (!workers_.size()) {
        if (!initialize_new_worker(true)) {
            throw std::runtime_error("Unable to dispatch work");
        }
    }

    // Locate first available worker
    while (!did_fail) {
        auto it = std::find_if(workers_.begin(), workers_.end(), [](const std::unique_ptr<RecoveryWorker>& w) {
            return w->get_status() == RecoveryWorker::Status::Idle;
        });

        if (it != workers_.end()) {
            SILKWORM_LOG(LogLevel::Debug) << "Dispatching package " << batch_id_ << " worker "
                                          << (std::distance(workers_.begin(), it)) << std::endl;
            (*it)->set_work(batch_id_++, std::move(batch_));  // Transfers ownership of batch to worker
            if (renew) {
                init_batch();
            }
            break;
        } else {
            // Do we have ready results from workers that we need to bufferize ?
            it = std::find_if(workers_.begin(), workers_.end(), [](const std::unique_ptr<RecoveryWorker>& w) {
                auto s = static_cast<int>(w->get_status());
                return (s >= 2);
            });
            if (it != workers_.end()) {
                did_fail = bufferize_workers_results();
                continue;
            }

            // We don't have a worker available
            // Maybe we can create a new one if available
            if (workers_.size() != max_workers_) {
                if (!initialize_new_worker(false)) {
                    max_workers_ = workers_.size();  // Don't try to spawn new workers. Maybe we're OOM
                } else {
                    continue;
                }
            }

            // No other option than wait a while and retry
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    };
    if (did_fail) {
        throw std::runtime_error("Unable to dispatch work");
    }
}

bool RecoveryFarm::initialize_new_worker(bool show_error) {
    SILKWORM_LOG(LogLevel::Debug) << "Launching worker #" << workers_.size() << std::endl;

    try {
        workers_.emplace_back(new RecoveryWorker(workers_.size(), max_batch_size_ * kAddressLength));
        workers_.back()->signal_completed.connect(boost::bind(&RecoveryFarm::worker_completed_handler, this, _1, _2));
        workers_.back()->start(/*wait = */ true);
        return workers_.back()->get_state() == Worker::WorkerState::kStarted;
    } catch (const std::exception& ex) {
        if (show_error) {
            SILKWORM_LOG(LogLevel::Error) << "Unable to initialize recovery worker : " << ex.what() << std::endl;
        }
        return false;
    }
}

StageResult RecoveryFarm::fill_canonical_headers(uint64_t height_from, uint64_t height_to) {
    SILKWORM_LOG(LogLevel::Info) << "Loading canonical headers [" << height_from << " .. " << height_to << "]"
                                 << std::endl;

    // Locate starting canonical header selected
    uint64_t expected_block_num{height_from};
    uint64_t reached_block_num{0};
    auto hashes_table{db::open_cursor(db_transaction_, db::table::kCanonicalHashes)};
    auto header_key{db::block_key(expected_block_num)};
    auto data{hashes_table.find(db::to_slice(header_key), false)};

    if (!data) {
        SILKWORM_LOG(LogLevel::Error) << "Header " << expected_block_num << " not found" << std::endl;
        return StageResult::kBadChainSequence;
    }

    // Read all headers up to block_to included
    while (data) {
        reached_block_num = boost::endian::load_big_u64(static_cast<uint8_t*>(data.key.iov_base));
        if (reached_block_num != expected_block_num) {
            SILKWORM_LOG(LogLevel::Error) << "Bad header hash sequence ! Expected " << expected_block_num << " got "
                                          << reached_block_num << std::endl;
            return StageResult::kBadChainSequence;
        }

        if (data.value.length() != kHashLength) {
            throw std::runtime_error("Bad header hash at height " + std::to_string(reached_block_num));
        }

        // We have a canonical header hash in right sequence
        headers_.push_back(to_bytes32(db::from_slice(data.value)));
        expected_block_num++;
        data = hashes_table.to_next(false);
    }

    // If we've not reached block_to something is wrong
    if (reached_block_num != height_to) {
        return StageResult::kBadChainSequence;
    }

    return StageResult::kSuccess;
}

void RecoveryFarm::worker_completed_handler(RecoveryWorker* sender, uint32_t batch_id) {
    // Ensure worker threads complete batches in the same order they
    // were launched
    while (completed_batch_id.load() != batch_id) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Save my ids in the queue of results to
    // store in db
    std::lock_guard l(batches_completed_mtx);
    std::pair<uint32_t, uint32_t> item{sender->get_id(), batch_id};
    batches_completed.push(item);
    completed_batch_id++;
}

void RecoveryFarm::init_batch() {
    batch_ = std::make_unique<std::vector<RecoveryWorker::package>>();
    (*batch_).reserve(max_batch_size_);
}

}  // namespace silkworm::stagedsync::recovery
