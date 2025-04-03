// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/datastore/etl/collector.hpp>
#include <silkworm/db/datastore/etl/collector_settings.hpp>
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
        db::DataModelFactory data_model_factory,
        const ChainConfig& chain_config,
        size_t batch_size,
        datastore::etl::CollectorSettings etl_settings,
        db::BlockAmount prune_mode_senders);
    ~Senders() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

    void set_prune_mode_senders(db::BlockAmount prune_mode_senders);

  private:
    Stage::Result parallel_recover(db::RWTxn& txn);

    Stage::Result add_to_batch(BlockNum block_num, BlockTime block_timestamp, const Hash& block_hash, const std::vector<Transaction>& transactions);
    void recover_batch(ThreadPool& worker_pool, const secp256k1_context* context);
    void collect_senders();
    void collect_senders(std::shared_ptr<AddressRecoveryBatch>& batch);
    void store_senders(db::RWTxn& txn);

    void increment_total_processed_blocks();
    void increment_total_collected_transactions(size_t delta);

    db::DataModelFactory data_model_factory_;
    const ChainConfig& chain_config_;
    db::BlockAmount prune_mode_senders_;

    //! The size of recovery batches
    size_t max_batch_size_;

    //! The current recovery batch being created
    std::shared_ptr<AddressRecoveryBatch> batch_;

    //! The sequence of completed batch futures
    std::vector<std::future<std::shared_ptr<AddressRecoveryBatch>>> results_;

    //! The total count of collected senders
    uint64_t collected_senders_{0};

    //! ETL collector writing recovered senders in bulk
    datastore::etl::CollectorSettings etl_settings_;
    std::unique_ptr<datastore::kvdb::Collector> collector_;

    // Stats
    std::mutex mutex_{};
    size_t total_processed_blocks_{0};
    size_t total_collected_transactions_{0};
    std::string current_key_{};
};

}  // namespace silkworm::stagedsync
