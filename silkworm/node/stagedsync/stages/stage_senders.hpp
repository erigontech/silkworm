/*
   Copyright 2022 The Silkworm Authors

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

#include <secp256k1.h>

#include <future>
#include <memory>
#include <mutex>
#include <vector>

#include <evmc/evmc.h>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/db/etl/collector.hpp>
#include <silkworm/db/etl/collector_settings.hpp>
#include <silkworm/db/prune_mode.hpp>
#include <silkworm/db/stage.hpp>
#include <silkworm/infra/concurrency/thread_pool.hpp>

namespace silkworm::stagedsync {

//! \brief The information to compute the sender address from transaction signature
struct AddressRecovery {
    BlockNum block_num{0};       // Number of block containing the transaction
    Hash block_hash;             // Hash of the block containing the transaction
    bool odd_y_parity{false};    // Whether y parity is odd (https://eips.ethereum.org/EIPS/eip-155)
    uint8_t tx_signature[64]{};  // Signature of the transaction
    evmc::address tx_from;       // Recovered sender address
    Bytes rlp;                   // RLP representation of the transaction
};

using AddressRecoveryBatch = std::vector<AddressRecovery>;

class Senders final : public Stage {
  public:
    Senders(
        SyncContext* sync_context,
        const ChainConfig& chain_config,
        size_t batch_size,
        const db::etl::CollectorSettings& etl_settings,
        db::BlockAmount prune_mode_senders);
    ~Senders() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

    void set_prune_mode_senders(db::BlockAmount prune_mode_senders);

  private:
    Stage::Result parallel_recover(db::RWTxn& txn);

    Stage::Result add_to_batch(BlockNum block_num, const Hash& block_hash, const std::vector<Transaction>& transactions);
    void recover_batch(ThreadPool& worker_pool, secp256k1_context* context);
    void collect_senders();
    void collect_senders(std::shared_ptr<AddressRecoveryBatch>& batch);
    void store_senders(db::RWTxn& txn);

    void increment_total_processed_blocks();
    void increment_total_collected_transactions(std::size_t delta);

    const ChainConfig& chain_config_;
    db::BlockAmount prune_mode_senders_;

    //! The size of recovery batches
    std::size_t max_batch_size_;

    //! The current recovery batch being created
    std::shared_ptr<AddressRecoveryBatch> batch_;

    //! The sequence of completed batch futures
    std::vector<std::future<std::shared_ptr<AddressRecoveryBatch>>> results_;

    //! The total count of collected senders
    uint64_t collected_senders_{0};

    //! ETL collector writing recovered senders in bulk
    db::etl::CollectorSettings etl_settings_;
    std::unique_ptr<db::etl_mdbx::Collector> collector_{nullptr};

    // Stats
    std::mutex mutex_{};
    std::size_t total_processed_blocks_{0};
    std::size_t total_collected_transactions_{0};
    std::string current_key_{};
};

}  // namespace silkworm::stagedsync
