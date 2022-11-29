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

#include <silkworm/concurrency/containers.hpp>
#include <silkworm/consensus/engine.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/downloader/internals/types.hpp>
#include <silkworm/stagedsync/stage.hpp>

namespace silkworm::stagedsync {

class BodiesStage : public Stage {
  public:
    BodiesStage(NodeSettings*, SyncContext*);
    BodiesStage(const BodiesStage&) = delete;  // not copyable
    BodiesStage(BodiesStage&&) = delete;       // nor movable
    ~BodiesStage() = default;

    Stage::Result forward(db::RWTxn&) override;  // go forward, downloading headers
    Stage::Result unwind(db::RWTxn&) override;   // go backward, unwinding headers to new_height
    Stage::Result prune(db::RWTxn&) override;

  private:
    std::vector<std::string> get_log_progress() override;  // thread safe
    std::atomic<BlockNum> current_height_{0};

  protected:
    class BodyDataModel {
      public:
        explicit BodyDataModel(db::RWTxn&, BlockNum bodies_stage_height, const ChainConfig&);
        ~BodyDataModel() = default;

        void update_tables(const Block&);
        void close();

        static void remove_bodies(BlockNum new_height, std::optional<Hash> bad_block, db::RWTxn& tx);

        bool unwind_needed() const;

        BlockNum unwind_point() const;
        BlockNum initial_height() const;
        BlockNum highest_height() const;
        Hash bad_block() const;

        void set_preverified_height(BlockNum height);

      private:
        using ConsensusEnginePtr = std::unique_ptr<consensus::IEngine>;

        ConsensusEnginePtr consensus_engine_;
        db::Buffer chain_state_;

        BlockNum initial_height_{0};
        BlockNum highest_height_{0};

        BlockNum preverified_height_{0};

        BlockNum unwind_point_{0};
        bool unwind_needed_{false};
        Hash bad_block_;
    };
};

}  // namespace silkworm::stagedsync
