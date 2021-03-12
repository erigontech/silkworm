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

#include <atomic>
#include <csignal>
#include <queue>
#include <string>
#include <thread>

#include <CLI/CLI.hpp>
#include <boost/endian.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/signals2.hpp>
#include <ethash/keccak.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/worker.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/types/block.hpp>

namespace fs = boost::filesystem;
using namespace silkworm;

std::atomic_bool g_should_stop{false};  // Request for stop from user or OS

struct app_options_t {
    std::string datadir{};                                      // Provided database path
    uint64_t mapsize{0};                                        // Provided lmdb map size
    uint32_t max_workers{std::thread::hardware_concurrency()};  // Max number of threads
    size_t batch_size{1'000'000};                               // Number of work packages to serve a worker
    uint32_t block_from{1u};                                    // Initial block number to start from
    uint32_t block_to{UINT32_MAX};                              // Final block number to process
    bool force{false};                                          // Whether to replay already processed blocks
    bool dry{false};                                            // Runs in dry mode (no data is persisted on disk)
    bool debug{false};                                          // Whether to display some debug info
};

void sig_handler(int signum) {
    (void)signum;
    std::cout << std::endl << " Got interrupt. Stopping ..." << std::endl << std::endl;
    g_should_stop.store(true);
}

/**
 * @brief A thread worker dedicated at recovering public keys from
 * transaction signatures
 */
class RecoveryWorker final : public silkworm::Worker {
  public:
    RecoveryWorker(uint32_t id, size_t data_size) : id_(id), data_size_{data_size} {
        // Try allocate enough memory to store
        // results output
        data_ = static_cast<uint8_t*>(std::calloc(1, data_size_));
        if (!data_) {
            throw std::runtime_error("Memory allocation failed");
        }
    };

    // Recovery package
    struct package {
        uint64_t block_num;
        ethash::hash256 hash;
        bool odd_y_parity;
        uint8_t signature[64];
    };

    enum class Status {
        Idle = 0,
        Working = 1,
        ResultsReady = 2,
        Error = 3,
        Aborted = 4,
    };

    // Provides a container of packages to process
    void set_work(uint32_t batch_id, std::unique_ptr<std::vector<package>> batch) {
        batch_ = std::move(batch);
        batch_id_ = batch_id;
        status_.store(Status::Working);
        Worker::kick();
    }

    uint32_t get_id() const { return id_; };
    uint32_t get_batch_id() const { return batch_id_; };
    std::string get_error(void) const { return last_error_; };
    Status get_status(void) const { return status_.load(); };

    // Pull results from worker
    bool pull_results(Status status, std::vector<std::pair<uint64_t, MDB_val>>& out) {
        if (status_.compare_exchange_strong(status, Status::Idle)) {
            std::swap(out, results_);
            return true;
        };
        return false;
    };

    // Signal to connected handlers the task has completed
    boost::signals2::signal<void(RecoveryWorker* sender, uint32_t batch_id)> signal_completed;

  private:
    const uint32_t id_;                                    // Current worker identifier
    uint32_t batch_id_{0};                                 // Running batch identifier
    std::unique_ptr<std::vector<package>> batch_;          // Batch to process
    size_t data_size_;                                     // Size of the recovery data buffer
    uint8_t* data_{nullptr};                               // Pointer to data where rsults are stored
    std::vector<std::pair<uint64_t, MDB_val>> results_{};  // Results per block pointing to data area
    std::string last_error_{};                             // Description of last error occurrence
    std::atomic<Status> status_{Status::Idle};             // Status of worker

    // Basic work loop (overrides Worker::work())
    void work() final {
        while (wait_for_kick()) {
            // Prefer swapping with a new vector instead of clear
            std::vector<std::pair<uint64_t, MDB_val>>().swap(results_);

            uint64_t block_num{(*batch_).front().block_num};
            size_t block_result_offset{0};
            size_t block_result_length{0};

            for (auto const& package : (*batch_)) {
                // On block switching store the results
                if (block_num != package.block_num) {
                    MDB_val result{block_result_length, &data_[block_result_offset]};
                    results_.push_back({block_num, result});
                    block_result_offset += block_result_length;
                    block_result_length = 0;
                    block_num = package.block_num;
                    if (should_stop()) {
                        status_.store(Status::Aborted);
                        break;
                    }
                }

                std::optional<Bytes> recovered{
                    ecdsa::recover(full_view(package.hash.bytes), full_view(package.signature), package.odd_y_parity)};

                if (recovered.has_value() && recovered->at(0) == 4u) {
                    auto keyHash{ethash::keccak256(recovered->data() + 1, recovered->length() - 1)};
                    std::memcpy(&data_[block_result_offset + block_result_length],
                                &keyHash.bytes[sizeof(keyHash) - kAddressLength], kAddressLength);
                    block_result_length += kAddressLength;
                } else {
                    last_error_ = "Public key recovery failed at block #" + std::to_string(package.block_num);
                    status_.store(Status::Error);
                    break;  // No need to process other txns
                }
            }

            if (status_.load() == Status::Working) {
                // Store results for last block
                if (block_result_length) {
                    MDB_val result{block_result_length, &data_[block_result_offset]};
                    results_.push_back({block_num, result});
                }
                status_.store(Status::ResultsReady);
            }

            // Raise finished event
            signal_completed(this, batch_id_);
            batch_.reset();
        }

        std::free(data_);
    };
};

/**
 * @brief An orchestrator of RecoveryWorkers
 */
class RecoveryFarm final {
  public:
    RecoveryFarm() = delete;

    /**
     * @brief This class coordinates the recovery of senders' addresses through
     * multiple threads. May eventually handle the unwinding of already
     * recovered addresses.
     *
     * @param transaction: the database transaction we should work on
     * @param max_workers: max number of recovery threads to spawn
     * @param max_batch_size: max number of transaction to be sent a worker for recovery
     */
    explicit RecoveryFarm(lmdb::Transaction& db_transaction, uint32_t max_workers, size_t max_batch_size,
                          etl::Collector& collector)
        : db_transaction_{db_transaction},
          max_workers_{max_workers},
          max_batch_size_{max_batch_size},
          collector_{collector} {
        workers_.reserve(max_workers);
    };
    ~RecoveryFarm() = default;

    enum class Status {
        Succeded = 0,
        DatabaseError = 1,
        HeaderNotFound = 2,
        BadHeaderSequence = 3,
        InvalidRange = 4,
        PrevStagesInadequate = 5,
        BlockNotFound = 6,
        BadBlockSequence = 7,
        InvalidTransactionSignature = 8,
        RecoveryError = 9,
        WorkerInitError = 10,
        WorkerAborted = 11,
        WorkerStatusMismatch = 12,
        FileSystemError = 13,
        InvalidChainConfig = 14,
        NoDataToProcess = 15,
    };

    /**
     * @brief Recovers sender's public keys from transactions
     *
     * @param height_from : Lower boundary for blocks to process (included)
     * @param height_to   : Upper boundary for blocks to process (included)
     */
    Status recover(uint64_t height_from, uint64_t height_to, bool force) {
        Status ret{Status::Succeded};

        auto config{db::read_chain_config(db_transaction_)};
        if (!config.has_value()) {
            return Status::InvalidChainConfig;
        }

        try {
            // Retrieve previous stage height
            auto senders_stage_height{db::stages::get_stage_progress(db_transaction_, db::stages::kSendersKey)};
            if (height_from > (senders_stage_height + 1)) {
                height_from = (senders_stage_height + 1);
            }
            if (height_from <= senders_stage_height) {
                if (force) {
                    uint64_t new_height{height_from ? height_from - 1 : height_from};
                    Status ret_status = unwind(new_height);
                    if (ret_status != Status::Succeded) {
                        return ret_status;
                    }
                    db::stages::set_stage_progress(db_transaction_, db::stages::kSendersKey, new_height);
                } else {
                    height_from = senders_stage_height + 1;
                }
            }

            auto blocks_stage_height{db::stages::get_stage_progress(db_transaction_, db::stages::kBlockBodiesKey)};
            if (height_to > blocks_stage_height) {
                height_to = blocks_stage_height;
                if (height_to < height_from) {
                    // We actually don't need to recover anything
                    return Status::NoDataToProcess;
                }
            }

            if (height_from > height_to) {
                return Status::InvalidRange;
            }

            // Load canonical headers
            Status ret_status{Status::Succeded};
            uint64_t headers_count{height_to - height_from + 1};
            headers_.reserve(headers_count);
            ret_status = fill_canonical_headers(height_from, height_to);
            if (ret_status != Status::Succeded) {
                return ret_status;
            }

            SILKWORM_LOG(LogLevels::LogInfo) << "Collected " << headers_.size() << " canonical headers" << std::endl;
            if (headers_.size() != headers_count) {
                SILKWORM_LOG(LogLevels::LogError) << "A total of " << headers_count << " was expected" << std::endl;
                return Status::HeaderNotFound;
            }

            headers_it_1_ = headers_.begin();
            headers_it_2_ = headers_.begin();

            // Load block bodies
            uint64_t block_num{0};                     // Block number being processed
            uint64_t expected_block_num{height_from};  // Expected block number in sequence

            SILKWORM_LOG(LogLevels::LogDebug) << "Begin read block bodies ... " << std::endl;
            auto bodies_table{db_transaction_.open(db::table::kBlockBodies)};
            auto transactions_table{db_transaction_.open(db::table::kEthTx)};

            // Set to first block and read all in sequence
            auto block_key{db::block_key(expected_block_num, headers_it_1_->bytes)};
            MDB_val mdb_key{db::to_mdb_val(block_key)}, mdb_data{};
            int rc{bodies_table->seek_exact(&mdb_key, &mdb_data)};
            if (rc) {
                return Status::BlockNotFound;
            }

            // Initializes first batch
            init_batch();

            while (!rc && !should_stop()) {
                auto key_view{db::from_mdb_val(mdb_key)};
                block_num = boost::endian::load_big_u64(key_view.data());
                if (block_num < expected_block_num) {
                    // The same block height has been recorded
                    // but is not canonical;
                    rc = bodies_table->get_next(&mdb_key, &mdb_data);
                    continue;
                } else if (block_num > expected_block_num) {
                    // We surpassed the expected block which means
                    // either the db misses a block or blocks are not persisted
                    // in sequence
                    SILKWORM_LOG(LogLevels::LogError) << "Senders' recovery : Bad block sequence expected "
                                                      << expected_block_num << " got " << block_num << std::endl;
                    return Status::BadBlockSequence;
                }

                if (memcmp(&key_view[8], headers_it_1_->bytes, 32) != 0) {
                    // We stumbled into a non canonical block (not matching header)
                    // move next and repeat
                    rc = bodies_table->get_next(&mdb_key, &mdb_data);
                    continue;
                }

                // Get the body and its transactions
                auto body_rlp{db::from_mdb_val(mdb_data)};
                auto block_body{db::detail::decode_stored_block_body(body_rlp)};
                std::vector<Transaction> transactions{
                    db::read_transactions(*transactions_table, block_body.base_txn_id, block_body.txn_count)};

                if (transactions.size()) {
                    if (((*batch_).size() + transactions.size()) > max_batch_size_) {
                        ret = dispatch_batch();
                        if (ret != Status::Succeded) {
                            throw std::runtime_error("Unable to dispatch work");
                        }
                    }

                    ret = fill_batch(*config, block_num, transactions);
                    if (ret != Status::Succeded) {
                        throw std::runtime_error("Unable to transform transactions");
                    }
                }

                // After processing move to next block number and header
                if (++headers_it_1_ == headers_.end()) {
                    // We'd go beyond collected canonical headers
                    break;
                }

                expected_block_num++;
                rc = bodies_table->get_next(&mdb_key, &mdb_data);
            }

            if (rc && rc != MDB_NOTFOUND) {
                lmdb::err_handler(rc);
            }

            SILKWORM_LOG(LogLevels::LogDebug) << "End   read block bodies ... " << std::endl;

            if (!should_stop() && !static_cast<int>(ret)) {
                ret = dispatch_batch(/* renew = */ false);
                if (ret != Status::Succeded) {
                    throw std::runtime_error("Unable to dispatch work");
                }
            }

        } catch (const lmdb::exception& ex) {
            SILKWORM_LOG(LogLevels::LogError) << "Senders' recovery : Database error " << ex.what() << std::endl;
            ret = Status::DatabaseError;
        } catch (const std::exception& ex) {
            SILKWORM_LOG(LogLevels::LogError) << "Senders' recovery : " << ex.what() << std::endl;
            ret = Status::RecoveryError;
        }

        // If everything ok from previous steps wait for all workers to complete
        // and bufferize results
        if (!static_cast<int>(ret)) {
            wait_workers_completion();
            bufferize_workers_results();
            if (collector_.size() && !should_stop()) {
                try {
                    // Prepare target table
                    auto target_table = db_transaction_.open(db::table::kSenders, MDB_CREATE);
                    SILKWORM_LOG(LogLevels::LogInfo)
                        << "ETL Load [2/2] : Loading data into " << target_table->get_name() << std::endl;
                    collector_.load(
                        target_table.get(), nullptr, MDB_APPEND,
                        /* log_every_percent = */ (total_recovered_transactions_ <= max_batch_size_ ? 1 : 20));
                    db::stages::set_stage_progress(db_transaction_, db::stages::kSendersKey, last_processed_block_);
                } catch (const lmdb::exception& ex) {
                    SILKWORM_LOG(LogLevels::LogError)
                        << "Senders' recovery : Database error " << ex.what() << std::endl;
                    ret = Status::DatabaseError;
                } catch (const std::exception& ex) {
                    SILKWORM_LOG(LogLevels::LogError) << "Senders' recovery : " << ex.what() << std::endl;
                    ret = Status::RecoveryError;
                }
            }
        }

        SILKWORM_LOG(LogLevels::LogDebug) << "Stopping workers ... " << std::endl;
        stop_all_workers(/*wait = */ true);
        return ret;
    }

    /**
     * @brief Unwinds Sender's recovery stage
     */
    Status unwind(uint64_t new_height) {
        SILKWORM_LOG(LogLevels::LogInfo) << "Unwinding Senders' table to height " << new_height << std::endl;
        try {
            auto unwind_table{db_transaction_.open(db::table::kSenders, MDB_CREATE)};
            size_t rcount{0};
            lmdb::err_handler(unwind_table->get_rcount(&rcount));
            if (rcount) {
                if (new_height <= 1) {
                    lmdb::err_handler(unwind_table->clear());
                } else {
                    Bytes key(40, '\0');
                    boost::endian::store_big_u64(&key[0], new_height + 1);  // New stage height is last processed
                    MDB_val mdb_key{db::to_mdb_val(key)}, mdb_data{};
                    lmdb::err_handler(unwind_table->seek(&mdb_key, &mdb_data));
                    do {
                        /* Delete all records sequentially */
                        lmdb::err_handler(unwind_table->del_current());
                        lmdb::err_handler(unwind_table->get_next(&mdb_key, &mdb_data));
                    } while (true);
                }
            }
        } catch (const lmdb::exception& ex) {
            if (ex.err() != MDB_NOTFOUND) {
                SILKWORM_LOG(LogLevels::LogError)
                    << "Senders Unwinding : Unexpected database error :  " << ex.what() << std::endl;
                return Status::DatabaseError;
            }
        }
        return Status::Succeded;
    }

  private:
    /**
     * @brief Gets whether or not this class should stop working
     */
    bool should_stop() { return should_stop_.load() || g_should_stop.load(); }

    /**
     * @brief Forces each worker to stop
     */
    void stop_all_workers(bool wait = true) {
        for (const auto& worker : workers_) {
            worker->stop(wait);
        }
    }

    /**
     * @brief Waits till every worker has finished or aborted
     */
    void wait_workers_completion() {
        if (workers_.size()) {
            uint64_t attempts{0};
            do {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                auto it = std::find_if(workers_.begin(), workers_.end(), [](const std::unique_ptr<RecoveryWorker>& w) {
                    return w->get_status() == RecoveryWorker::Status::Working;
                });
                if (it == workers_.end()) {
                    break;
                }
                attempts++;
                if (!(attempts % 10)) {
                    SILKWORM_LOG(LogLevels::LogDebug) << "Waiting for workers to complete" << std::endl;
                }
            } while (true);
        }
    }

    /**
     * @brief Collects results from worker's completed tasks
     */
    Status bufferize_workers_results() {
        static std::string fmt_row{"%10u bks %12u txs"};

        Status ret{Status::Succeded};
        std::vector<std::pair<uint64_t, MDB_val>> worker_results{};
        do {
            // Check we have results to pull
            std::unique_lock l(batches_completed_mtx);
            if (batches_completed.empty()) {
                break;
            }

            // Pull results
            auto& item{batches_completed.front()};
            auto& worker{workers_.at(item.first)};
            batches_completed.pop();
            l.unlock();

            auto status = worker->get_status();
            if (status == RecoveryWorker::Status::Error) {
                SILKWORM_LOG(LogLevels::LogError)
                    << "Got error from worker id " << worker->get_id() << " : " << worker->get_error() << std::endl;
                ret = Status::RecoveryError;
                break;
            } else if (status == RecoveryWorker::Status::Aborted) {
                ret = Status::WorkerAborted;
                break;
            } else if (status == RecoveryWorker::Status::ResultsReady) {
                if (!worker->pull_results(status, worker_results)) {
                    ret = Status::WorkerStatusMismatch;
                    break;
                } else {
                    for (auto& [block_num, mdb_val] : worker_results) {
                        last_processed_block_ = block_num;
                        total_processed_blocks_++;
                        total_recovered_transactions_ += (mdb_val.mv_size / kAddressLength);

                        auto etl_key{db::block_key(block_num, headers_it_2_->bytes)};
                        Bytes etl_data(db::from_mdb_val(mdb_val));
                        etl::Entry entry{etl_key, etl_data};
                        collector_.collect(entry);  // TODO check for errors (eg. disk full)
                        headers_it_2_++;
                    }
                    SILKWORM_LOG(LogLevels::LogInfo)
                        << "ETL Load [1/2] : "
                        << (boost::format(fmt_row) % total_processed_blocks_ % total_recovered_transactions_)
                        << std::endl;
                }
            }

            worker_results.clear();

        } while (!should_stop());

        if (ret != Status::Succeded) {
            should_stop_.store(true);
        }

        return ret;
    }

    /**
     * @brief Transforms transaction into recoverable packages
     *
     * @param config       : Chain configuration
     * @param block_num    : Actual block this transactions belong to
     * @param transactions : Transactions which have to be reovered for sender address
     */
    Status fill_batch(ChainConfig config, uint64_t block_num, std::vector<Transaction>& transactions) {
        for (const auto& transaction : transactions) {
            if (!silkworm::ecdsa::is_valid_signature(transaction.r, transaction.s, config.has_homestead(block_num))) {
                SILKWORM_LOG(LogLevels::LogError)
                    << "Got invalid signature in transaction for block " << block_num << std::endl;
                return Status::InvalidTransactionSignature;
            }

            if (transaction.chain_id) {
                if (!config.has_spurious_dragon(block_num)) {
                    SILKWORM_LOG(LogLevels::LogError)
                        << "EIP-155 signature in transaction before Spurious Dragon for block " << block_num
                        << std::endl;
                    return Status::InvalidTransactionSignature;
                } else if (*transaction.chain_id != config.chain_id) {
                    SILKWORM_LOG(LogLevels::LogError)
                        << "EIP-155 invalid signature in transaction for block " << block_num << std::endl;
                    SILKWORM_LOG(LogLevels::LogError) << "Expected chain_id " << config.chain_id << " got "
                                                      << intx::to_string(*transaction.chain_id) << std::endl;
                    return Status::InvalidTransactionSignature;
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

        return Status::Succeded;
    }

    /**
     * @brief Dispatches the collected batch of data to first available worker.
     * Eventually creates worksers up to max_workers
     */
    Status dispatch_batch(bool renew = true) {
        Status ret{Status::Succeded};
        if (!batch_ || !(*batch_).size() || should_stop()) {
            return ret;
        }

        // First worker created
        if (!workers_.size()) {
            if (!initialize_new_worker(/*show_error =*/true)) {
                ret = Status::WorkerInitError;
            }
        }

        // Locate first available worker
        while (ret == Status::Succeded) {
            auto it = std::find_if(workers_.begin(), workers_.end(), [](const std::unique_ptr<RecoveryWorker>& w) {
                return w->get_status() == RecoveryWorker::Status::Idle;
            });

            if (it != workers_.end()) {
                SILKWORM_LOG(LogLevels::LogDebug)
                    << "Dispatching package to worker #" << (std::distance(workers_.begin(), it)) << std::endl;
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
                    SILKWORM_LOG(LogLevels::LogDebug) << "Bufferize results" << std::endl;
                    ret = bufferize_workers_results();
                    continue;
                }

                // We don't have a worker available
                // Maybe we can create a new one if available
                if (workers_.size() != max_workers_) {
                    if (!initialize_new_worker()) {
                        max_workers_ = workers_.size();  // Don't try to spawn new workers. Maybe we're OOM
                    }
                }

                // No other option than wait a while and retry
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        };

        return ret;
    }

    bool initialize_new_worker(bool show_error = false) {
        SILKWORM_LOG(LogLevels::LogDebug) << "Launching worker #" << workers_.size() << std::endl;

        try {
            workers_.emplace_back(new RecoveryWorker(workers_.size(), max_batch_size_ * kAddressLength));
            workers_.back()->signal_completed.connect(
                boost::bind(&RecoveryFarm::worker_completed_handler, this, _1, _2));
            workers_.back()->start(/*wait = */ true);
            return workers_.back()->get_state() == Worker::WorkerState::kStarted;
        } catch (const std::exception& ex) {
            if (show_error) {
                SILKWORM_LOG(LogLevels::LogError)
                    << "Unable to initialize recovery worker : " << ex.what() << std::endl;
            }
            return false;
        }
    }

    /**
     * @brief Fills a vector of all canonical headers
     *
     * @param headers     : Storage vector for all headers
     * @param height_from : Lower boundary for canonical headers (included)
     * @param height_to   : Upper boundary for canonical headers (included)
     */
    Status fill_canonical_headers(uint64_t height_from, uint64_t height_to) {
        SILKWORM_LOG(LogLevels::LogInfo) << "Loading canonical headers [" << height_from << " .. " << height_to << "]"
                                         << std::endl;

        try {
            // Locate starting canonical header selected
            uint64_t expected_block_num{height_from};
            uint64_t reached_block_num{0};
            auto headers_table{db_transaction_.open(db::table::kBlockHeaders)};
            auto header_key{db::header_hash_key(expected_block_num)};
            MDB_val mdb_key{db::to_mdb_val(header_key)}, mdb_data{};

            int rc{headers_table->seek_exact(&mdb_key, &mdb_data)};
            if (rc) {
                if (rc == MDB_NOTFOUND) {
                    SILKWORM_LOG(LogLevels::LogError) << "Header " << expected_block_num << " not found" << std::endl;
                    return Status::HeaderNotFound;
                }
                lmdb::err_handler(rc);
            }

            // Read all headers up to block_to included
            while (!rc) {
                if (mdb_key.mv_size == header_key.length() && mdb_data.mv_size) {
                    ByteView data_view{static_cast<uint8_t*>(mdb_key.mv_data), mdb_key.mv_size};
                    if (data_view[8] == 'n') {
                        reached_block_num = boost::endian::load_big_u64(&data_view[0]);
                        if (reached_block_num != expected_block_num) {
                            SILKWORM_LOG(LogLevels::LogError) << "Bad header sequence ! Expected " << expected_block_num
                                                              << " got " << reached_block_num << std::endl;
                            return Status::BadHeaderSequence;
                        }

                        // We have a canonical header in right sequence
                        headers_.push_back(to_bytes32(db::from_mdb_val(mdb_data)));
                        expected_block_num++;

                        // Don't pass upper boundary
                        if (reached_block_num == height_to) {
                            break;
                        }
                    }
                }
                rc = headers_table->get_next(&mdb_key, &mdb_data);
            }

            if (rc && rc != MDB_NOTFOUND) {
                lmdb::err_handler(rc);
            }

            // If we've not reached block_to something is wrong
            if (reached_block_num != height_to) {
                return Status::HeaderNotFound;
            }

            return Status::Succeded;

        } catch (const lmdb::exception& ex) {
            SILKWORM_LOG(LogLevels::LogError)
                << "Load canonical headers : Unexpected database error :  " << ex.what() << std::endl;
            return Status::DatabaseError;
        }
    }

    /**
     * @brief Gets executed by worker on its work completed
     */
    void worker_completed_handler(RecoveryWorker* sender, uint32_t batch_id) {
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

    /**
     * @brief Initializes a new batch container
     */
    void init_batch() {
        batch_ = std::make_unique<std::vector<RecoveryWorker::package>>();
        (*batch_).reserve(max_batch_size_);
    }

    friend class RecoveryWorker;
    lmdb::Transaction& db_transaction_;  // Database transaction

    /* Recovery workers */
    uint32_t max_workers_;                                    // Max number of workers/threads
    std::vector<std::unique_ptr<RecoveryWorker>> workers_{};  // Actual collection of recoverers

    /* Canonical headers */
    std::vector<evmc::bytes32> headers_{};               // Collected canonical headers
    std::vector<evmc::bytes32>::iterator headers_it_1_;  // For blocks reading
    std::vector<evmc::bytes32>::iterator headers_it_2_;  // For buffer results

    /* Batches */
    const size_t max_batch_size_;  // Max number of transaction to be sent a worker for recovery
    std::unique_ptr<std::vector<RecoveryWorker::package>>
        batch_;                                  // Collection of transactions to be sent a worker for recovery
    uint32_t batch_id_{0};                       // Incremental id of launched batches
    std::atomic_uint32_t completed_batch_id{0};  // Incremental id of completed batches
    std::queue<std::pair<uint32_t, uint32_t>>
        batches_completed{};           // Queue of batches completed waiting to be written on disk
    std::mutex batches_completed_mtx;  // Guards the queue
    etl::Collector& collector_;

    std::atomic_bool should_stop_{false};

    /* Stats */
    uint64_t total_recovered_transactions_{0};
    uint64_t total_processed_blocks_{0};
    uint64_t last_processed_block_{0};
};

int main(int argc, char* argv[]) {
    // Init command line parser
    CLI::App app("Senders recovery tool.");
    app_options_t options{};
    options.datadir = db::default_path();  // Default chain data db path

    // Command line arguments
    app.add_option("--chaindata", options.datadir, "Path to chain db", true)->check(CLI::ExistingDirectory);

    std::string mapSizeStr{"0"};
    app.add_option("--lmdb.mapSize", mapSizeStr, "Lmdb map size", true);

    app.add_option("--workers", options.max_workers, "Max number of worker threads", true)
        ->check(CLI::Range(1u, std::thread::hardware_concurrency()));

    app.add_option("--from", options.block_from, "Initial block number to process (inclusive)", true)
        ->check(CLI::Range(1u, UINT32_MAX));
    app.add_option("--to", options.block_to, "Final block number to process (inclusive)", true)
        ->check(CLI::Range(1u, UINT32_MAX));

    app.add_option("--batch", options.batch_size, "Number of transactions to process per batch", true)
        ->check(CLI::Range(1'000u, 10'000'000u));

    app.add_flag("--debug", options.debug, "May print some debug/trace info.");
    app.add_flag("--force", options.force, "Force reprocessing of blocks");
    app.add_flag("--dry", options.dry, "Runs the full cycle but nothing is persisted");

    app.require_subcommand(1);  // One of the following subcommands is required
    auto& app_recover = *app.add_subcommand("recover", "Recovers Senders' addresses");
    auto& app_unwind = *app.add_subcommand("unwind", "Unwinds Senders' stage to given height");

    CLI11_PARSE(app, argc, argv);

    if (options.debug) {
        SILKWORM_LOG_VERBOSITY(LogDebug);
    }

    auto lmdb_mapSize{parse_size(mapSizeStr)};
    if (!lmdb_mapSize.has_value()) {
        std::cerr << "Provided --lmdb.mapSize \"" << mapSizeStr << "\" is invalid" << std::endl;
        return -1;
    }
    if (*lmdb_mapSize) {
        // Adjust mapSize to a multiple of page_size
        size_t host_page_size{boost::interprocess::mapped_region::get_page_size()};
        options.mapsize = ((*lmdb_mapSize + host_page_size - 1) / host_page_size) * host_page_size;
    }
    if (!options.block_from) options.block_from = 1u;  // Block 0 (genesis) has no transactions

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // If database path is provided (and has passed CLI::ExistingDirectory validator
    // check whether it is empty
    fs::path db_path(options.datadir);
    if (!fs::exists(db_path) || !fs::is_directory(db_path) || fs::is_empty(db_path)) {
        std::cerr << "Invalid or empty --chaindata \"" << options.datadir << "\"" << std::endl
                  << "Try --help for help" << std::endl;
        return -1;
    } else {
        fs::path db_file = fs::path(db_path / fs::path("data.mdb"));
        if (!fs::exists(db_file) || !fs::file_size(db_file)) {
            std::cerr << "Invalid or empty data file \"" << db_file.string() << "\"" << std::endl
                      << "Try --help for help" << std::endl;
            return -1;
        }
    }

    // Invoke proper action
    int rc{0};
    try {
        if (!app_recover && !app_unwind) {
            throw std::runtime_error("Invalid operation");
        }

        // Set database parameters
        lmdb::DatabaseConfig db_config{options.datadir};
        db_config.set_readonly(false);
        db_config.map_size = options.mapsize;

        // Compute etl temporary path
        fs::path etl_path(db_path.parent_path() / fs::path("etl-temp"));
        fs::create_directories(etl_path);
        etl::Collector collector(etl_path.string().c_str(), /* flush size */ 512 * kMebi);

        // Open db and transaction
        auto lmdb_env{lmdb::get_env(db_config)};
        auto lmdb_txn{lmdb_env->begin_rw_transaction()};

        // Create farm instance and do work
        RecoveryFarm farm(*lmdb_txn, options.max_workers, options.batch_size, collector);
        RecoveryFarm::Status result{RecoveryFarm::Status::Succeded};

        if (app_recover) {
            result = farm.recover(options.block_from, options.block_to, options.force);
        } else {
            result = farm.unwind(options.block_from);
        }

        if (rc = static_cast<int>(result), rc) {
            SILKWORM_LOG(LogLevels::LogError)
                << (app_recover ? "Recovery" : "Unwind") << " returned code " << rc << std::endl;
        } else {
            if (!options.dry) {
                SILKWORM_LOG(LogLevels::LogInfo) << "Committing" << std::endl;
                lmdb::err_handler(lmdb_txn->commit());
            }
        }

    } catch (const fs::filesystem_error& ex) {
        SILKWORM_LOG(LogLevels::LogError) << ex.what() << " Check your filesystem permissions" << std::endl;
        rc = static_cast<int>(RecoveryFarm::Status::FileSystemError);
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevels::LogError) << ex.what() << std::endl;
        rc = static_cast<int>(RecoveryFarm::Status::DatabaseError);
    }

    return rc;
}
