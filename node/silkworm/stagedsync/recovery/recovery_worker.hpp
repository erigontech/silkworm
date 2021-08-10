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
#include <filesystem>
#include <queue>
#include <string>
#include <thread>

#include <CLI/CLI.hpp>
#include <boost/endian.hpp>
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

#ifndef SILKWORM_STAGEDSYNC_RECOVERY_WORKER_HPP_
#define SILKWORM_STAGEDSYNC_RECOVERY_WORKER_HPP_

namespace silkworm::stagedsync::recovery {

/**
 * @brief A thread worker dedicated at recovering public keys from
 * transaction signatures
 */
class RecoveryWorker final : public silkworm::Worker {
  public:
    RecoveryWorker(uint32_t id, size_t data_size);

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
    void set_work(uint32_t batch_id, std::unique_ptr<std::vector<package>> batch);

    uint32_t get_id() const;
    uint32_t get_batch_id() const;
    std::string get_error(void) const;
    Status get_status(void) const;

    // Pull results from worker
    bool pull_results(Status status, std::vector<std::pair<uint64_t, iovec>>& out);

    // Signal to connected handlers the task has completed
    boost::signals2::signal<void(RecoveryWorker* sender, uint32_t batch_id)> signal_completed;

  private:
    const uint32_t id_;                                  // Current worker identifier
    uint32_t batch_id_{0};                               // Running batch identifier
    std::unique_ptr<std::vector<package>> batch_;        // Batch to process
    size_t data_size_;                                   // Size of the recovery data buffer
    uint8_t* data_{nullptr};                             // Pointer to data where rsults are stored
    std::vector<std::pair<uint64_t, iovec>> results_{};  // Results per block pointing to data area
    std::string last_error_{};                           // Description of last error occurrence
    std::atomic<Status> status_{Status::Idle};           // Status of worker

    // Basic work loop (overrides Worker::work())
    void work() final;
};

}  // namespace silkworm::stagedsync::recovery

#endif
