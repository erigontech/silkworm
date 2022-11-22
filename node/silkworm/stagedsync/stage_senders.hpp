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

#include <mutex>
#include <vector>

#include <evmc/evmc.h>
#include <silkpre/ecdsa.h>

#include <silkworm/common/base.hpp>
#include <silkworm/stagedsync/stage.hpp>

namespace silkworm::stagedsync {

//! \brief A recovery package
struct RecoveryPackage {  // TODO(canepat) rename AddressRecovery
    BlockNum block_num{0};       // Block number this package refers to
    ethash::hash256 tx_hash{};   // Keccak hash of transaction's rlp representation
    bool odd_y_parity{false};    // Whether y parity is odd (https://eips.ethereum.org/EIPS/eip-155)
    uint8_t tx_signature[64]{};  // Signature of transaction
    evmc::address tx_from;       // Recovered address
};

class Senders final : public Stage {
  public:
    explicit Senders(NodeSettings* node_settings, SyncContext* sync_context);
    ~Senders() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    Stage::Result parallel_recover(db::RWTxn& txn);

    Stage::Result read_canonical_headers(db::ROTxn& txn, BlockNum from, BlockNum to) noexcept;

    Stage::Result add_to_batch(BlockNum block_num, std::vector<Transaction>&& transactions);

    //!
    void recover_batch(secp256k1_context* context, BlockNum from);

    //!
    void collect_senders(BlockNum from);

    //!
    void store_senders(db::RWTxn& txn);

    //!
    void increment_phase();
    void increment_total_processed_blocks();
    void increment_total_collected_transactions(std::size_t delta);

    //!
    std::vector<evmc::bytes32> canonical_hashes_;

    //! The size of recovery batches.
    std::size_t max_batch_size_;

    //!
    std::vector<RecoveryPackage> batch_;

    //! ETL collector writing recovered senders in bulk
    etl::Collector collector_;

    // Stats
    std::mutex mutex_{};
    uint16_t current_phase_{0};
    std::size_t total_processed_blocks_{0};
    std::size_t total_collected_transactions_{0};
    std::string current_key_{};
};

}  // namespace silkworm::stagedsync
