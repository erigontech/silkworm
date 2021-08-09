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

#ifndef SILKWORM_STAGEDSYNC_RECOVERY_FARM_HPP_
#define SILKWORM_STAGEDSYNC_RECOVERY_FARM_HPP_

#include <atomic>

#include <silkworm/stagedsync/recovery/recovery_worker.hpp>
#include <silkworm/stagedsync/util.hpp>

namespace silkworm::stagedsync::recovery {

/**
 * @brief An orchestrator of RecoveryWorkers
 */
class RecoveryFarm {
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
    RecoveryFarm(mdbx::txn& db_transaction, uint32_t max_workers, size_t max_batch_size, etl::Collector& collector);
    ~RecoveryFarm() = default;

    /**
     * @brief Recovers sender's public keys from transactions
     *
     * @param height_from : Lower boundary for blocks to process (included)
     * @param height_to   : Upper boundary for blocks to process (included)
     */
    StageResult recover(uint64_t height_from, uint64_t height_to);

    /**
     * @brief Unwinds Sender's recovery stage
     */
    StageResult unwind(uint64_t new_height);

    void stop() { should_stop_.store(true); }

  private:
    /**
     * @brief Gets whether or not this class should stop working
     */
    bool should_stop() { return should_stop_.load(); }

    /**
     * @brief Forces each worker to stop
     */
    void stop_all_workers(bool wait = true);

    /**
     * @brief Waits till every worker has finished or aborted
     */
    void wait_workers_completion();

    /**
     * @brief Collects results from worker's completed tasks
     */
    bool bufferize_workers_results();

    /**
     * @brief Transforms transaction into recoverable packages
     *
     * @param config       : Chain configuration
     * @param block_num    : Actual block this transactions belong to
     * @param transactions : Transactions which have to be recovered for sender address
     */
    void fill_batch(ChainConfig config, uint64_t block_num, std::vector<Transaction>& transactions);

    /**
     * @brief Dispatches the collected batch of data to first available worker.
     * Eventually creates worksers up to max_workers
     */
    void dispatch_batch(bool renew);

    bool initialize_new_worker(bool show_error);
    /**
     * @brief Fills a vector of all canonical headers
     *
     * @param headers     : Storage vector for all headers
     * @param height_from : Lower boundary for canonical headers (included)
     * @param height_to   : Upper boundary for canonical headers (included)
     */
    StageResult fill_canonical_headers(uint64_t height_from, uint64_t height_to);

    /**
     * @brief Gets executed by worker on its work completed
     */
    void worker_completed_handler(RecoveryWorker* sender, uint32_t batch_id);
    /**
     * @brief Initializes a new batch container
     */
    void init_batch();

    friend class RecoveryWorker;
    mdbx::txn& db_transaction_;  // Database transaction

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
};

}  // namespace silkworm::stagedsync::recovery

#endif  // SILKWORM_STAGEDSYNC_RECOVERY_FARM_HPP_
