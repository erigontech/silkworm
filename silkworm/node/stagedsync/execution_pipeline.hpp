// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/core/types/hash.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/datastore/stage_scheduler.hpp>
#include <silkworm/db/stage.hpp>
#include <silkworm/infra/common/timer.hpp>
#include <silkworm/node/common/node_settings.hpp>

#include "timer_factory.hpp"

namespace silkworm::stagedsync {

using StageContainer = std::map<std::string_view, std::unique_ptr<Stage>>;
using StageContainerFactory = std::function<StageContainer(SyncContext&)>;

class ExecutionPipeline : public Stoppable {
  public:
    using StageNames = std::vector<const char*>;
    static StageNames stages_forward_order();
    static StageNames stages_unwind_order();

    ExecutionPipeline(
        db::DataModelFactory data_model_factory,
        std::optional<TimerFactory> log_timer_factory,
        const StageContainerFactory& stages_factory);
    ~ExecutionPipeline() override = default;

    Stage::Result forward(db::RWTxn&, BlockNum target_block_num);
    Stage::Result unwind(db::RWTxn&, BlockNum unwind_point);
    Stage::Result prune(db::RWTxn&);

    BlockNum head_header_number() const;
    Hash head_header_hash() const;
    std::optional<BlockNum> unwind_point();
    std::optional<Hash> bad_block();

    bool stop() override;

    datastore::StageScheduler& stage_scheduler() const;

  private:
    db::DataModelFactory data_model_factory_;
    std::optional<TimerFactory> log_timer_factory_;
    std::unique_ptr<SyncContext> sync_context_;  // context shared across stages

    StageContainer stages_;
    StageContainer::iterator current_stage_;

    StageNames stages_forward_order_;
    StageNames stages_unwind_order_;
    std::atomic<size_t> current_stages_count_{0};
    std::atomic<size_t> current_stage_number_{0};

    BlockNum head_header_block_num_{0};
    Hash head_header_hash_;

    // Returns the current log lines prefix on behalf of current stage
    std::string get_log_prefix(const std::string_view& stage_name) const;

    std::shared_ptr<Timer> make_log_timer();
    bool log_timer_expired();
};

}  // namespace silkworm::stagedsync
