// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <boost/asio/io_context.hpp>

#include <silkworm/db/datastore/stage_scheduler.hpp>
#include <silkworm/db/stage.hpp>

namespace silkworm::stagedsync {

class TriggersStage : public Stage, public datastore::StageScheduler {
  public:
    explicit TriggersStage(SyncContext* sync_context);
    ~TriggersStage() override = default;

    Stage::Result forward(db::RWTxn& tx) override;
    Stage::Result unwind(db::RWTxn& txn) override;

    Stage::Result prune(db::RWTxn&) override { return Stage::Result::kSuccess; }

    Task<void> schedule(std::function<void(db::RWTxn&)> callback) override;

    bool stop() override;

  protected:
    boost::asio::io_context ioc_;

  private:
    db::RWTxn* current_tx_{};
};

}  // namespace silkworm::stagedsync
