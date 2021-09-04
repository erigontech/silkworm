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
#include <queue>

#include <silkworm/etl/collector.hpp>
#include <silkworm/stagedsync/recovery/recovery_worker.hpp>
#include <silkworm/stagedsync/util.hpp>

namespace silkworm::stagedsync::recovery {

//! \brief A class to orchestrate the work of multiple recoverers
class RecoveryFarm {
  public:
    RecoveryFarm() = delete;

    //! \brief This class coordinates the recovery of senders' addresses through multiple threads. May eventually handle
    //! the unwinding of already recovered addresses.
    //! \param [in] db_transaction : the database transaction we should work on
    //! \param [in] max_workers : max number of parallel recovery workers
    //! \param [in] max_batch_size : max number of transactions to be sent a worker for recovery
    RecoveryFarm(mdbx::txn& db_transaction, uint32_t max_workers, size_t max_batch_size, etl::Collector& collector);
    ~RecoveryFarm();

    //! \brief Recover sender's addresses from transactions
    //! \param [in] to :  Upper boundary for blocks to process (included)
    //! \return A code indicating process status
    StageResult recover(BlockNum to);

    //! \brief Issue an interruption request
    void stop() { should_stop_.store(true); }

    //! \brief Unwinds sender's recovery i.e. deletes recovered addresses from storage
    //! \param [in] db_transaction : the database transaction we should work on
    //! \param [in] new_height : the new height at which senders' addresses will be registered as recovered in storage
    //! \return A code indicating process status
    static StageResult unwind(mdbx::txn& db_transaction, BlockNum new_height);

  private:
    //! \brief Whether running tasks should stop
    bool should_stop() { return should_stop_.load(); }

    //! \brief Commands every threaded recovery worker to stop
    //! \param [in] wait : whether to wait for worker stopped
    void stop_all_workers(bool wait = true);

    //! \brief Make the farm wait for every threaded worker to stop
    void wait_workers_completion();

    //! \brief Collects results from worker's completed tasks
    bool collect_workers_results();

    //! \brief Transforms transactions into recoverable packages
    //! \param [in] config : active chain configuration
    //! \param [in] block_num : block number owning this set of transactions
    //! \param [in] transactions : a set of transactions to transform
    //! \return A code indicating process status
    //! \remarks If detects a batch overflow it also dispatches
    StageResult transform_and_fill_batch(const ChainConfig& config, BlockNum block_num,
                                         std::vector<Transaction>& transactions);

    //! \brief Dispatches the collected batch of recovery packages to first available worker
    //! \returns True if operation succeeds, false otherwise
    //! \remarks May spawn new worker(s) up to max_workers
    bool dispatch_batch();

    //! \brief Spawns a new threaded worker
    bool initialize_new_worker();

    //! \brief Fills a vector of all canonical headers
    //! \param [in] from : Lower boundary for blocks to process (included)
    //! \param [in] to :  Upper boundary for blocks to process (included)
    //! \return A code indicating process status
    StageResult fill_canonical_headers(BlockNum from, BlockNum to) noexcept;

    //! \brief Handle completion signal from workers
    void worker_completed_handler(RecoveryWorker* sender);

    friend class RecoveryWorker;
    mdbx::txn& db_transaction_;  // Database transaction

    using harvest_pair = std::pair<uint32_t, uint32_t>;  // Worker id + batch id
    using worker_pair = std::pair<std::unique_ptr<RecoveryWorker>, boost::signals2::connection>;

    /* Recovery workers */
    uint32_t max_workers_;                        // Max number of workers/threads
    std::vector<worker_pair> workers_{};          // Actual collection of recoverers
    std::mutex harvest_mutex_;                    // Guards the harvest queue
    std::queue<harvest_pair> harvest_pairs_{};    // Queue of harvest pairs
    std::atomic<uint32_t> workers_in_flight_{0};  // Counter of grinding workers

    /* Canonical headers */
    std::vector<evmc::bytes32> headers_{};               // Collected canonical headers
    std::vector<evmc::bytes32>::iterator headers_it_1_;  // For blocks reading
    BlockNum header_index_offset_{};                     // To retrieve proper header hash while harvesting

    /* Batches */
    size_t max_batch_size_;                        // Max number of transaction to be sent a worker for recovery
    uint32_t batch_id_{0};                         // Incremental id of launched batches
    std::atomic<uint32_t> completed_batch_id_{0};  // Incremental id of completed batches
    std::vector<RecoveryPackage> batch_;           // Collection of transactions to be sent a worker for recovery
    etl::Collector& collector_;

    std::atomic_bool should_stop_{false};

    /* Stats */
    size_t total_recovered_transactions_{0};
    size_t total_processed_blocks_{0};
};

}  // namespace silkworm::stagedsync::recovery

#endif  // SILKWORM_STAGEDSYNC_RECOVERY_FARM_HPP_
