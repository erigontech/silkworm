// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/stage.hpp>
#include <silkworm/infra/concurrency/containers.hpp>

namespace silkworm::stagedsync {

class BodiesStage : public Stage {
  public:
    BodiesStage(
        SyncContext* sync_context,
        const ChainConfig& chain_config,
        db::DataModelFactory data_model_factory,
        std::function<BlockNum()> last_pre_validated_block);
    BodiesStage(const BodiesStage&) = delete;  // not copyable
    BodiesStage(BodiesStage&&) = delete;       // nor movable
    ~BodiesStage() override = default;

    Stage::Result forward(db::RWTxn&) override;  // go forward, downloading headers
    Stage::Result unwind(db::RWTxn&) override;   // go backward, unwinding headers to new_block_num
    Stage::Result prune(db::RWTxn&) override;

  private:
    std::vector<std::string> get_log_progress() override;  // thread safe

    const ChainConfig& chain_config_;
    db::DataModelFactory data_model_factory_;
    std::function<BlockNum()> last_pre_validated_block_;
    std::atomic<BlockNum> current_block_num_{0};

  protected:
    // BodyDataModel has the responsibility to update bodies related tables
    class BodyDataModel {
      public:
        explicit BodyDataModel(
            db::RWTxn& tx,
            db::DataModel data_model,
            BlockNum bodies_stage_block_num,
            const ChainConfig& chain_config);
        ~BodyDataModel() = default;

        void update_tables(const Block&);  // make a pre-verification of the body and update body related tables
        void close();

        // remove body data from tables, used in unwind phase
        static void remove_bodies(BlockNum new_block_num, std::optional<Hash> bad_block, db::RWTxn& tx);

        // holds the status of a batch insertion of bodies
        bool unwind_needed() const;
        BlockNum unwind_point() const;
        BlockNum initial_block_num() const;
        BlockNum max_block_num() const;
        Hash bad_block() const;

        bool get_canonical_block(BlockNum block_num, Block& block) const;

        void set_preverified_block_num(BlockNum block_num);

      private:
        db::DataModel data_model_;
        const ChainConfig& chain_config_;
        protocol::RuleSetPtr rule_set_;
        db::Buffer chain_state_;

        BlockNum initial_block_num_{0};
        BlockNum max_block_num_{0};

        BlockNum preverified_block_num_{0};

        BlockNum unwind_point_{0};
        bool unwind_needed_{false};
        Hash bad_block_;
    };
};

}  // namespace silkworm::stagedsync
