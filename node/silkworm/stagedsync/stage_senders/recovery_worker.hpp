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
    BlockNum block_num;        // Block number this package refers to
    ethash::hash256 tx_hash;   // Keccak hash of transaction's rlp representation
    bool odd_y_parity;         // Whether y parity is odd (https://eips.ethereum.org/EIPS/eip-155)
    uint8_t tx_signature[64];  // Signature of transaction
    evmc::address tx_from;     // Recovered address
};

//! \brief A threaded worker in charge to recover sender's addresses from transaction signatures
//! \remarks Inherits from silkworm::Worker
class RecoveryWorker final : public silkworm::Worker {
  public:
    //! \brief Creates an instance of recovery worker
    //! \param [in] id : unique identifier for this instance
    //! \remarks data_size is expressed as number of transactions to recover per batch times address size
    explicit RecoveryWorker(uint32_t id)
        : Worker("Address recoverer #" + std::to_string(id)), id_(id), context_{ecdsa::create_context()} {
        if (!context_) {
            throw std::runtime_error("Could not create elliptic curve context");
        }
    };
    ~RecoveryWorker() final;

    //! \brief Feed the worker with a new set of data to process
    //! \param [in] batch : collection of work packages
    //! \param [in] kick : whether to kick the worker
    void set_work(std::vector<RecoveryPackage>& farm_batch, bool kick = false);

    //! \brief Returns the identifier of this recoverer
    uint32_t get_id() const { return id_; }

    //! \brief Signals connected handlers a task is completed
    boost::signals2::signal<void(RecoveryWorker* sender)> signal_task_completed;

  private:
    const uint32_t id_;                   // Unique identifier
    std::vector<RecoveryPackage> batch_;  // Batch to process
    secp256k1_context* context_;          // Elliptic curve context;

    //! \brief Basic recovery work loop
    //! \remarks Overrides Worker::work()
    void work() final;
};

}  // namespace silkworm::stagedsync::recovery

#endif  // SILKWORM_STAGEDSYNC_RECOVERY_WORKER_HPP_
