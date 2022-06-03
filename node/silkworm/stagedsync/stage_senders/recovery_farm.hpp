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

#pragma once
#ifndef SILKWORM_STAGEDSYNC_RECOVERY_FARM_HPP_
#define SILKWORM_STAGEDSYNC_RECOVERY_FARM_HPP_

#include <atomic>
#include <queue>

#include <silkworm/concurrency/stoppable.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/stagedsync/common.hpp>
#include <silkworm/stagedsync/stage_senders/recovery_worker.hpp>

namespace silkworm::stagedsync::recovery {

//! \brief A class to orchestrate the work of multiple recoverers
class RecoveryFarm : public Stoppable {
  public:
    RecoveryFarm() = delete;

    //! \brief This class coordinates the recovery of senders' addresses through multiple threads. May eventually handle
    //! the unwinding of already recovered addresses.
    RecoveryFarm(db::RWTxn& txn, NodeSettings* node_settings);
    ~RecoveryFarm() = default;

    //! \brief Recover sender's addresses from transactions
    //! \return A code indicating process status
    StageResult recover();

    //! \brief Issue an interruption request
    bool stop() final {
        if (Stoppable::stop()) {
            stop_all_workers(false);
            return true;
        }
        return false;
    }

    //! \brief Unwinds sender's recovery i.e. deletes recovered addresses from storage
    //! \param [in] db_transaction : the database transaction we should work on
    //! \param [in] new_height : the new height at which senders' addresses will be registered as recovered in storage
    //! \return A code indicating process status
    static StageResult unwind(mdbx::txn& db_transaction, BlockNum new_height);

    //! \brief Returns a collection of progress strings to be printed in log
    [[nodiscard]] std::vector<std::string> get_log_progress();

  private:
    friend class RecoveryWorker;
    friend class ::silkworm::Worker;

    //! \brief Commands every threaded recovery worker to stop
    //! \param [in] wait : whether to wait for worker stopped
    void stop_all_workers(bool wait = true);

    //! \brief Make the farm wait for every threaded worker to stop
    void wait_workers_completion();

    //! \brief Gets the first harvestable worker in the queue
    std::optional<size_t> get_harvestable_worker();

    //! \brief Collects results from worker's completed tasks
    bool collect_workers_results();

    //! \brief Transforms transactions into recoverable packages
    //! \param [in] block_num : block number owning this set of transactions
    //! \param [in] transactions : a set of transactions to transform
    //! \return A code indicating process status
    //! \remarks If detects a batch overflow it also dispatches
    StageResult transform_and_fill_batch(BlockNum block_num, const std::vector<Transaction>& transactions);

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

    //! \brief Handle task completion signal from workers
    void task_completed_handler(RecoveryWorker* sender);

    //! \brief Handle worker terminated signal from workers
    void worker_completed_handler(Worker* sender);

    db::RWTxn& txn_;               // Managed transaction
    NodeSettings* node_settings_;  // Global node settings
    etl::Collector collector_;     // Reserved collector

    /* Recovery workers */
    uint32_t max_workers_{std::thread::hardware_concurrency()};  // Max number of workers/threads

    std::vector<boost::signals2::scoped_connection> workers_connections_{};  // Hold event connections to workers
    std::vector<std::unique_ptr<RecoveryWorker>> workers_{};                 // Actual collection of recoverers

    std::mutex workers_mtx_{};  // Synchronize with workers
    std::condition_variable worker_completed_cv_{};
    std::queue<size_t> harvestable_workers_{};    // Queue of ready to harvest workers
    std::atomic<uint32_t> workers_in_flight_{0};  // Counter of grinding workers

    /* Canonical blocks + headers */
    struct HeaderInfo {
        HeaderInfo(uint32_t count, const evmc::bytes32& hash) : txn_count(count), block_hash{hash} {};
        uint32_t txn_count;
        evmc::bytes32 block_hash;
    };
    std::vector<HeaderInfo> headers_{};               // Collected canonical headers
    std::vector<HeaderInfo>::iterator headers_it_1_;  // For blocks reading
    BlockNum header_index_offset_{};                  // To retrieve proper header hash while harvesting

    /* Batches */
    size_t batch_size_;                   // Max number of transaction to be sent a worker for recovery
    std::vector<RecoveryPackage> batch_;  // Collection of transactions to be sent a worker for recovery

    /* Stats */
    uint16_t current_phase_{0};
    size_t total_processed_blocks_{0};
    size_t total_collected_transactions_{0};
};

}  // namespace silkworm::stagedsync::recovery

#endif  // SILKWORM_STAGEDSYNC_RECOVERY_FARM_HPP_
