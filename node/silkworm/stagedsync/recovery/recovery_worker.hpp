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

#pragma once
#ifndef SILKWORM_STAGEDSYNC_RECOVERY_WORKER_HPP_
#define SILKWORM_STAGEDSYNC_RECOVERY_WORKER_HPP_

#include <atomic>
#include <csignal>
#include <string>

#include <boost/signals2.hpp>
#include <ethash/keccak.hpp>

#include <silkworm/concurrency/worker.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/db/util.hpp>

namespace silkworm::stagedsync::recovery {

//! \brief A recovery package
struct RecoveryPackage {
    BlockNum block_num;     // Block number this package refers to
    ethash::hash256 hash;   // Keccak hash of transaction's rlp representation
    bool odd_y_parity;      // Whether y parity is odd (https://eips.ethereum.org/EIPS/eip-155)
    uint8_t signature[64];  // Signature of transaction
};

//! \brief A threaded worker in charge to recover sender's addresses from transaction signatures
//! \remarks Inherits from silkworm::Worker
class RecoveryWorker final : public silkworm::Worker {
  public:
    //! \brief Status of Recovery worker
    enum class Status {
        Idle = 0,          // Waiting for task
        Working = 1,       // Processing task
        ResultsReady = 2,  // Results ready to collect
        Error = 3,         // Some error encountered. Higher level RecoveryFarm should stop processing
        Aborted = 4,       // A user request for cancellation has been intercepted
    };

    //! \brief Creates an instance of recovery worker
    //! \param [in] id : unique identifier for this instance
    //! \param [in] data_size: sets the amount of memory to allocate for recovered addresses
    //! \remarks data_size is expressed as number of transactions to recover per batch times address size
    explicit RecoveryWorker(uint32_t id, size_t data_size);

    ~RecoveryWorker();

    //! \brief Feed the worker with a new set of data to process
    //! \param [in] batch_id : identifier of work batch
    //! \param [in] batch : collection of work packages
    void set_work(uint32_t batch_id, std::vector<RecoveryPackage>& farm_batch);

    //! \brief Return the instance unique identifier
    uint32_t get_id() const { return id_; };

    //! \brief Return the current batch identifier this instance is working on
    uint32_t get_batch_id() const { return batch_id_; };

    //! \brief Return the last error encountered by this Recoverer
    //! \return A string. If empty means no error found
    std::string get_error() const;

    //! \brief Return the Status of this Recoverer
    Status get_status() const;

    //! \brief Serves the processed results to higher level
    //! \param [in/out] out_results : a reference to a vector for results
    //! \return True if the accrued results have been fed into out_results. False otherwise
    //! \remarks This operates oa swap of contents among instance held results and provided reference
    bool pull_results(std::vector<std::pair<BlockNum, ByteView>>& out_results);

    //! \brief Signals connected handlers a task is completed
    boost::signals2::signal<void(RecoveryWorker* sender)> signal_completed;

  private:
    const uint32_t id_;                                     // Current worker identifier
    uint32_t batch_id_{0};                                  // Current batch identifier
    std::vector<RecoveryPackage> batch_;                    // Batch to process
    Bytes data_;                                            // Results data buffer
    secp256k1_context* context_;                            // Elliptic curve context;
    std::vector<std::pair<BlockNum, ByteView>> results_{};  // Results per block pointing to data area
    std::string last_error_{};                              // Description of last error occurrence
    std::atomic<Status> status_{Status::Idle};              // Status of worker

    //! \brief Basic recovery work loop
    //! \remarks Overrides Worker::work()
    void work() final;
};

}  // namespace silkworm::stagedsync::recovery

#endif
