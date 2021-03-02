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

#include <CLI/CLI.hpp>
#include <atomic>
#include <boost/endian.hpp>
#include <boost/filesystem.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/signals2.hpp>
#include <csignal>
#include <ethash/keccak.hpp>
#include <iostream>
#include <queue>
#include <silkworm/chain/config.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/worker.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/types/block.hpp>
#include <string>
#include <thread>

namespace fs = boost::filesystem;
using namespace silkworm;

std::atomic_bool g_should_stop{false};  // Request for stop from user or OS

struct app_options_t {
    std::string datadir{};          // Provided database path
    uint64_t mapsize{0};            // Provided lmdb map size
    size_t batch_size{100'000};     // Number of work packages to serve e worker
    uint32_t block_from{1u};        // Initial block number to start from
    uint32_t block_to{UINT32_MAX};  // Final block number to process
    bool replay{false};             // Whether to replay already extracted senders
    bool debug{false};              // Whether to display some debug info
    bool rundry{false};             // Runs in dry mode (no data is persisted on disk)
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

    RecoveryWorker(uint32_t id, size_t data_size) : id_(id), data_size_{data_size} {};

    // Recovery package
    struct package {
        uint64_t block_num;
        ethash::hash256 hash;
        uint8_t recovery_id;
        uint8_t signature[64];
    };

    enum class Status
    {
        Idle = 0,
        Working = 1,
        ResultsReady = 2,
        Error = 3,
        Aborted = 4,
    };

    // Provides a container of packages to process
    void set_work(uint32_t batch_id, std::vector<package>& packages) {
        std::unique_lock l{xwork_};
        work_set_.swap(packages);
        batch_id_ = batch_id;
        Worker::kick();
    }

    uint32_t get_id() const { return id_; };
    uint32_t get_batch_id() const { return batch_id_; };
    std::string get_error(void) const { return last_error_; };
    Status get_status(void) const { return status_.load(); };

    // Pull results from worker
    void pull_results(std::vector<std::pair<uint64_t, MDB_val>>& out) {
        std::swap(out, results_);
        Status exp_status{ Status::ResultsReady };
        status_.compare_exchange_strong(exp_status, Status::Idle);
    };

    // Signal to connected handlers the task has completed
    boost::signals2::signal<void(RecoveryWorker* sender, uint32_t batch_id)> signal_completed;

  private:
    const uint32_t id_;                                    // Current worker identifier
    uint32_t batch_id_{0};                                 // Running batch identifier
    std::vector<package> work_set_{};                      // Work packages to process
    size_t data_size_;                                     // Size of the recovery data buffer
    uint8_t* data_{nullptr};                               // Pointer to data where rsults are stored
    std::vector<std::pair<uint64_t, MDB_val>> results_{};  // Results per block pointing to data area
    std::string last_error_{};                             // Description of last error occurrence
    std::atomic<Status> status_{Status::Idle};             // Status of worker

    // Basic work loop (overrides Worker::work())
    void work() final {
        // Try allocate enough memory to store
        // results output
        data_ = static_cast<uint8_t*>(std::calloc(1, data_size_));
        if (!data_) {
            throw std::runtime_error("Unable to allocate memory");
        }

        while (!should_stop()) {
            bool expected_kick_value{true};
            if (!kicked_.compare_exchange_strong(expected_kick_value, false, std::memory_order_relaxed)) {
                std::unique_lock l(xwork_);
                kicked_cv_.wait_for(l, std::chrono::seconds(1));
                continue;
            }

            // Lock mutex so no other jobs may be set
            std::unique_lock l{xwork_};
            status_.store(Status::Working);
            results_.clear();

            uint64_t block_num{work_set_.at(0).block_num};
            size_t block_result_offset{0};
            size_t block_result_length{0};

            // Loop
            for (auto const& package : work_set_) {
                // On block switching store the results
                if (block_num != package.block_num) {
                    MDB_val result{block_result_length, (void*)&data_[block_result_offset]};
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
                    ecdsa::recover(full_view(package.hash.bytes), full_view(package.signature), package.recovery_id)};
                if (recovered.has_value() && (int)recovered->at(0) == 4) {
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
                    MDB_val result{block_result_length, (void*)&data_[block_result_offset]};
                    results_.push_back({block_num, result});
                }
                status_.store(Status::ResultsReady);
            }

            // Raise finished event
            signal_completed(this, batch_id_);
            work_set_.clear();  // Clear here. Next set_work will swap the cleaned container to master thread
            l.unlock();
        }

        std::free(data_);
    };
};

/**
* @brief An orchestrator of RecoveryWorkers
*/
class RecoveryFarm final
{
public:

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
      batch_.reserve(max_batch_size);
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
  };

  /**
  * @brief Recovers sender's public keys from transactions
  *
  * @param height_from : Lower boundary for blocks to process (included)
  * @param height_to   : Upper boundary for blocks to process (included)
  */
  Status recover(ChainConfig config, uint64_t height_from, uint64_t height_to) {

      Status ret{Status::Succeded};
      try {

          if (height_from > height_to) {
              return Status::InvalidRange;
          }

          auto headers_stage_height{db::stages::get_stage_progress(db_transaction_, db::stages::kHeadersKey)};
          auto blocks_stage_height{db::stages::get_stage_progress(db_transaction_, db::stages::kBlockBodiesKey)};
          auto senders_stage_height{db::stages::get_stage_progress(db_transaction_, db::stages::kSendersKey)};

          // We need to have headers and blocks to proceed
          if (headers_stage_height < height_from || blocks_stage_height < height_from) {
              // We actually don't have anything to recover
              return Status::Succeded;
          }

          if (height_to == UINT64_MAX) {
              height_to = std::min(headers_stage_height, blocks_stage_height);
          }

          if (headers_stage_height < height_to || blocks_stage_height < height_to) {
              return Status::PrevStagesInadequate;
          }

          // Sanity checks
          if (height_from <= senders_stage_height) {
              uint64_t new_height{height_from ? height_from - 1 : height_from};
              Status ret_status = unwind(new_height);
              if (ret_status != Status::Succeded) {
                  return ret_status;
              }
              db::stages::set_stage_progress(db_transaction_, db::stages::kSendersKey, new_height);
          }

          // Load canonical headers
          Status ret_status{Status::Succeded};
          uint64_t headers_count{height_from - height_to + 1};
          headers_.reserve(headers_count);
          ret_status = fill_canonical_headers(height_from, height_to);
          if (ret_status != Status::Succeded) {
              return ret_status;
          } else {
              if (headers_.size() != headers_count) {
                  return Status::HeaderNotFound;
              }
          }

          SILKWORM_LOG(LogLevels::LogInfo) << "Collected " << headers_.size() << " canonical headers" << std::endl;

          // Load block bodies
          uint64_t block_num{0};                     // Block number being processed
          uint64_t expected_block_num{height_from};  // Expected block number in sequence

          SILKWORM_LOG(LogLevels::LogInfo) << "Scanning block bodies ... " << std::endl;
          auto bodies_table{db_transaction_.open(db::table::kBlockBodies)};
          auto transactions_table{db_transaction_.open(db::table::kEthTx)};

          // Set to first block and read all in sequence
          auto block_key{db::block_key(height_from, headers_it_1_->bytes)};
          MDB_val mdb_key{db::to_mdb_val(block_key)}, mdb_data{};
          int rc{bodies_table->seek_exact(&mdb_key, &mdb_data)};
          if (rc) {
              return Status::BlockNotFound;
          }

          while (!rc && !should_stop())
          {
              auto key_view{ db::from_mdb_val(mdb_key) };
              block_num = boost::endian::load_big_u64(key_view.data());
              if (block_num < expected_block_num)
              {
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

              if (memcmp((void*)&key_view[8], (void*)headers_it_1_->bytes, 32) != 0) {
                  // We stumbled into a non canonical block (not matching header)
                  // move next and repeat
                  rc = bodies_table->get_next(&mdb_key, &mdb_data);
                  continue;
              }

              // Get the body and its transactions
              auto block_body{db::detail::decode_stored_block_body(db::from_mdb_val(mdb_data))};
              std::vector<Transaction> transactions{
                  db::read_transactions(*transactions_table, block_body.base_txn_id, block_body.txn_count)};

              if (transactions.size()) {

                  if ((batch_.size() + transactions.size()) > max_batch_size_) {
                      ret = dispatch_batch();
                      if (ret != Status::Succeded) {
                          throw std::runtime_error("Unable to dispatch work");
                      }
                  }

                  ret = fill_batch(config, block_num, transactions);
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

          if (!should_stop()) {
              dispatch_batch();  // Dispatch residual work
          } else {
              for (auto& w : workers_) {
                  w->stop(/*wait =*/true);
              }
          }

      } catch (const lmdb::exception& ex) {
          SILKWORM_LOG(LogLevels::LogError) << "Senders' recovery : Database error " << ex.what() << std::endl;
          ret = Status::DatabaseError;
      } catch (const std::exception& ex) {
          SILKWORM_LOG(LogLevels::LogError) << "Senders' recovery : " << ex.what() << std::endl;
      }

      // Wait for all threads to stop
      do {
          auto it = std::find_if(workers_.begin(), workers_.end(), [](const std::unique_ptr<RecoveryWorker>& w) {
              return w->get_status() == RecoveryWorker::Status::Working;
          });
          if (it == workers_.end()) {
              break;
          }
          std::this_thread::sleep_for(std::chrono::seconds(1));
      } while (true);

      // Bufferize residual results
      bufferize_workers_results();
  }

  /**
  * @brief Unwinds Sender's recovery stage
  */
  Status unwind(uint64_t new_height) {
      SILKWORM_LOG(LogLevels::LogInfo) << "Unwinding Senders' table to height " << new_height << std::endl;
      try {
          auto unwind_table{db_transaction_.open(db::table::kSenders, MDB_CREATE)};
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
      } catch (const lmdb::exception& ex) {
          if (ex.err() != MDB_NOTFOUND) {
              SILKWORM_LOG(LogLevels::LogError)
                  << "Senders Unwinding : Unexpected database error :  " << ex.what() << std::endl;
              return Status::DatabaseError;
          }
      }
      return Status::Succeded;
  }

protected:

    /**
    * @brief Gets whether or not this class should stop working
    */
    bool should_stop() {

        // TODO Handle interrupt signal
        return should_stop_.load() || g_should_stop.load();
    }

    /**
    * @brief Collects results from worker's completed tasks
    */
    Status bufferize_workers_results() {

        Status ret{Status::Succeded};
        std::vector<std::pair<uint64_t, MDB_val>> worker_results{};
        do
        {
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
                should_stop_.store(true, std::memory_order_relaxed);
                ret = Status::RecoveryError;
            } else if (status == RecoveryWorker::Status::Aborted) {
                ret = Status::WorkerAborted;
            } else if (status == RecoveryWorker::Status::ResultsReady) {
                worker->pull_results(worker_results);
                // Save results in etl
                if (!should_stop()) {
                    for (auto& [block_num, mdb_val] : worker_results) {
                        auto etl_key{db::block_key(block_num, headers_it_2_->bytes)};
                        Bytes etl_data(static_cast<unsigned char*>(mdb_val.mv_data), mdb_val.mv_size);
                        etl::Entry item{etl_key, etl_data};
                        collector_.collect(item);  // TODO check for errors (eg. disk full)
                        headers_it_2_++;
                    }
                }
            }

            worker_results.clear();
        } while (ret == Status::Succeded && !should_stop());

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
        for (const auto& transaction: transactions)
        {
            if (!silkworm::ecdsa::is_valid_signature(transaction.r, transaction.s, config.has_homestead(block_num))) {
                SILKWORM_LOG(LogLevels::LogError) << "Got invalid signature in transaction for block " << block_num << std::endl;
                return Status::InvalidTransactionSignature;
            }

            ecdsa::RecoveryId x{ ecdsa::get_signature_recovery_id(transaction.v) };
            Bytes rlp{};
            if (x.eip155_chain_id) {
                if (!config.has_spurious_dragon(block_num)) {
                    SILKWORM_LOG(LogLevels::LogError) << "EIP-155 signature in transaction before Spurious Dragon for block " << block_num << std::endl;
                    return Status::InvalidTransactionSignature;
                } else if (x.eip155_chain_id != config.chain_id) {

                    SILKWORM_LOG(LogLevels::LogError)
                        << "EIP-155 invalid signature in transaction for block " << block_num << std::endl;
                    SILKWORM_LOG(LogLevels::LogError) << "Expected chain_id " << config.chain_id << " got "
                                                      << intx::to_string(*x.eip155_chain_id) << std::endl;
                    return Status::InvalidTransactionSignature;
                }
                rlp::encode(rlp, transaction, true, { config.chain_id });
            } else {
                rlp::encode(rlp, transaction, true, {});
            }

            auto hash{keccak256(rlp)};
            RecoveryWorker::package package{block_num, hash, x.recovery_id};
            intx::be::unsafe::store(package.signature, transaction.r);
            intx::be::unsafe::store(package.signature + 32, transaction.s);
            batch_.push_back(package);

        }

        return Status::Succeded;
    }

    /**
    * @brief Dispatches the collected batch of data to first available worker.
    * Eventually creates worksers up to max_workers
    */
    Status dispatch_batch() {

        Status ret{Status::Succeded};
        if (!batch_.size() || should_stop()) {
            return ret;
        }

        // Locate first available worker
        while (ret == Status::Succeded) {

            auto it = std::find_if(workers_.begin(), workers_.end(), [](const std::unique_ptr<RecoveryWorker>& w) {
                return w->get_status() == RecoveryWorker::Status::Idle;
            });

            if (it != workers_.end()) {
                (*it)->set_work(batch_id_++, batch_);
                break;
            } else {

                // First worker created
                if (!workers_.size()) {
                    if (!initialize_new_worker(/*show_error =*/ true)) {
                        return Status::WorkerInitError;
                    }
                    continue;
                }

                // Do we have ready results from workers ?
                it = std::find_if(workers_.begin(), workers_.end(), [](const std::unique_ptr<RecoveryWorker>& w) {
                    auto s = w->get_status();
                    return (s == RecoveryWorker::Status::Aborted || s == RecoveryWorker::Status::Error ||
                            s == RecoveryWorker::Status::ResultsReady);
                });
                if (it != workers_.end()) {
                    ret = bufferize_workers_results();
                    continue;
                }

                // We don't have a worker available
                // Maybe we can create a new one if available
                if (workers_.size() != max_workers_) {
                    if (initialize_new_worker()) {
                        max_workers_ = workers_.size(); // Don't try to spawn new workers. Maybe we're OOM
                        continue;
                    }
                }

                // No other option than wait a while and retry
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        };

        return ret;
    }

    bool initialize_new_worker(bool show_error = false) {

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

        const uint64_t count{height_to - height_to + 1};
        SILKWORM_LOG(LogLevels::LogInfo) << "Loading canonical block headers [" << height_from << " ... " << height_to
                                         << "] ... " << std::endl;

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
                    return Status::HeaderNotFound;
                }
                return Status::DatabaseError;
            }

            // Read all headers up to block_to included
            while (!rc) {
                if (mdb_key.mv_size == header_key.length() && mdb_data.mv_size) {
                    ByteView data_view{static_cast<uint8_t*>(mdb_key.mv_data), mdb_key.mv_size};
                    if (data_view[8] == 'n') {
                        reached_block_num = boost::endian::load_big_u64(&data_view[0]);
                        if (reached_block_num != expected_block_num) {
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
            SILKWORM_LOG(LogLevels::LogError) << "Load canonical headers : Unexpected database error :  " << ex.what() << std::endl;
            return Status::DatabaseError;
        }
    }

    /**
     * @brief Gets executed by worker on its work completed
     */
    void worker_completed_handler(RecoveryWorker* sender, uint32_t batch_id) {
        // Ensure worker threads complete batches in the same order they
        // were launched
        while (completed_batch_id.load(std::memory_order_relaxed) != batch_id) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        auto returned_error = sender->get_error();
        if (!returned_error.empty()) {
            should_stop_.store(true, std::memory_order_relaxed);
        }

        // Save my ids in the queue of results to
        // store in db
        std::lock_guard l(batches_completed_mtx);
        std::pair<uint32_t, uint32_t> item{sender->get_id(), batch_id};
        batches_completed.push(item);
        completed_batch_id++;
    }

private:

  friend class RecoveryWorker;
  lmdb::Transaction& db_transaction_;                       // Database transaction

  /* Recovery workers */
  uint32_t max_workers_;                                    // Max number of workers/threads
  std::vector<std::unique_ptr<RecoveryWorker>> workers_{};  // Actual collection of recoverers

  /* Canonical headers */
  std::vector<evmc::bytes32> headers_{};                                 // Collected canonical headers
  std::vector<evmc::bytes32>::iterator headers_it_1_{headers_.begin()};  // For blocks reading
  std::vector<evmc::bytes32>::iterator headers_it_2_{headers_.begin()};  // For buffer results

  /* Batches */
  const size_t max_batch_size_;                   // Max number of transaction to be sent a worker for recovery
  std::vector<RecoveryWorker::package> batch_{};  // Collection of transactions to be sent a worker for recovery
  uint32_t batch_id_{0};                          // Incremental id of launched batches
  std::atomic_uint32_t completed_batch_id{0};     // Incremental id of completed batches
  std::queue<std::pair<uint32_t, uint32_t>>
      batches_completed{};           // Queue of batches completed waiting to be written on disk
  std::mutex batches_completed_mtx;  // Guards the queue
  etl::Collector& collector_;

  std::atomic_bool should_stop_{false};
};

// Prints out info of block's transactions with senders
int do_verify(app_options_t& options) {
    // Adjust params
    if (options.block_to == UINT32_MAX) options.block_to = options.block_from;

    try {
        // Open db and start transaction
        lmdb::DatabaseConfig db_config{options.datadir};
        db_config.map_size = options.mapsize;
        std::shared_ptr<lmdb::Environment> lmdb_env{lmdb::get_env(db_config)};
        std::unique_ptr<lmdb::Transaction> lmdb_txn{lmdb_env->begin_ro_transaction()};
        std::unique_ptr<lmdb::Table> lmdb_headers{lmdb_txn->open(db::table::kBlockHeaders)};
        std::unique_ptr<lmdb::Table> lmdb_bodies{lmdb_txn->open(db::table::kBlockBodies)};
        std::unique_ptr<lmdb::Table> lmdb_senders{lmdb_txn->open(db::table::kSenders)};

        // Verify requested block is not beyond what we already have in chaindb
        size_t count{0};
        lmdb::err_handler(lmdb_senders->get_rcount(&count));
        if (!count) throw std::logic_error("Senders table is empty. Is the sync completed ?");
        lmdb::err_handler(lmdb_bodies->get_rcount(&count));
        if (!count) throw std::logic_error("Block bodies table is empty. Is the sync completed ?");
        lmdb::err_handler(lmdb_headers->get_rcount(&count));
        if (!count) throw std::logic_error("Headers table is empty. Is the sync completed ?");

        MDB_val key, data;
        lmdb::err_handler(lmdb_senders->get_last(&key, &data));
        ByteView v{static_cast<uint8_t*>(key.mv_data), key.mv_size};
        uint64_t most_recent_sender{boost::endian::load_big_u64(&v[0])};
        if (options.block_from > most_recent_sender) {
            throw std::logic_error("Selected block beyond collected senders");
        }

        for (uint32_t block_num = options.block_from; block_num <= options.block_to; block_num++) {
            std::cout << "Reading block #" << block_num << std::endl;
            std::optional<BlockWithHash> bh{db::read_block(*lmdb_txn, block_num, /*read_senders=*/true)};
            if (!bh) {
                throw std::logic_error("Could not locate block #" + std::to_string(block_num));
            }

            if (!bh->block.transactions.size()) {
                std::cout << "Block has 0 transactions" << std::endl;
                continue;
            }

            std::cout << std::right << std::setw(4) << std::setfill(' ') << "Tx"
                      << " " << std::left << std::setw(66) << std::setfill(' ') << "Hash"
                      << " " << std::left << std::setw(42) << std::setfill(' ') << "From"
                      << " " << std::left << std::setw(42) << std::setfill(' ') << "To" << std::endl;
            std::cout << std::right << std::setw(4) << std::setfill('-') << ""
                      << " " << std::left << std::setw(66) << std::setfill('-') << ""
                      << " " << std::left << std::setw(42) << std::setfill('-') << ""
                      << " " << std::left << std::setw(42) << std::setfill('-') << "" << std::endl;

            for (size_t i = 0; i < bh->block.transactions.size(); i++) {
                Bytes rlp{};
                rlp::encode(rlp, bh->block.transactions.at(i), /*forsigning*/ false, {});
                ethash::hash256 hash{ethash::keccak256(rlp.data(), rlp.length())};
                ByteView bv{hash.bytes, 32};
                std::cout << std::right << std::setw(4) << std::setfill(' ') << i << " 0x" << to_hex(bv) << " 0x"
                          << to_hex(*(bh->block.transactions.at(i).from)) << " 0x"
                          << to_hex(*(bh->block.transactions.at(i).to)) << std::endl;
            }

            std::cout << std::endl;
        }

    } catch (const std::logic_error& ex) {
        std::cout << ex.what() << std::endl;
        return -1;
    } catch (const std::exception& ex) {
        std::cout << "Unexpected error : " << ex.what() << std::endl;
        return -1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    // Init command line parser
    CLI::App app("Senders recovery tool.");
    app_options_t options{};
    options.datadir = silkworm::db::default_path();  // Default chain data db path

    // Command line arguments
    app.add_option("--datadir", options.datadir, "Path to chain db", true)->check(CLI::ExistingDirectory);

    std::string mapSizeStr{"0"};
    app.add_option("--lmdb.mapSize", mapSizeStr, "Lmdb map size", true);
    app.add_option("--batch", options.batch_size, "Number of transactions to process per batch", true)
        ->check(CLI::Range((size_t)1'000, (size_t)10'000'000));
    app.add_option("--from", options.block_from, "Initial block number to process (inclusive)", true)
        ->check(CLI::Range(1u, UINT32_MAX));
    app.add_option("--to", options.block_to, "Final block number to process (inclusive)", true)
        ->check(CLI::Range(1u, UINT32_MAX));
    app.add_flag("--debug", options.debug, "May print some debug/trace info.");
    app.add_flag("--replay", options.replay, "Replay transactions.");
    app.add_flag("--dry", options.rundry, "Runs the full cycle but nothing is persisted");

    app.require_subcommand(1);  // One of the following subcommands is required
    auto& app_recover = *app.add_subcommand("recover", "Recovers senders' addresses");
    auto& app_verify = *app.add_subcommand("verify", "Verifies senders' addresses for given block");

    CLI11_PARSE(app, argc, argv);

    Logger::default_logger().set_local_timezone(true);  // for compatibility with TG logging
    if (options.debug) {
        Logger::default_logger().verbosity = LogLevels::LogTrace;
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
    fs::path db_path = fs::path(options.datadir);
    if (!fs::exists(db_path) || !fs::is_directory(db_path) || fs::is_empty(db_path)) {
        std::cerr << "Invalid or empty --datadir \"" << options.datadir << "\"" << std::endl
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

    // Enable debug logging if required
    if (options.debug) {
        Logger::default_logger().verbosity = LogLevels::LogTrace;
    }

    // Invoke proper action
    int rc{-1};
    if (app_recover) {
        // TODO
    } else if (app_verify) {
        rc = do_verify(options);
    } else {
        std::cerr << "No command specified" << std::endl;
    }

    return rc;
}
