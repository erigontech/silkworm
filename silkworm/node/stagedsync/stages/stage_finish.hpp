// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <silkworm/db/stage.hpp>

namespace silkworm::stagedsync {

class Finish : public Stage {
  public:
    explicit Finish(SyncContext* sync_context, std::string build_info)
        : Stage(sync_context, db::stages::kFinishKey),
          build_info_(std::move(build_info)) {}
    ~Finish() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;

    // Finish does not prune.
    Stage::Result prune(db::RWTxn&) final { return Stage::Result::kSuccess; };

  private:
    std::string build_info_;
};
}  // namespace silkworm::stagedsync
