// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <vector>

#include <gmock/gmock.h>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>

namespace silkworm::execution::api {

//! \brief gMock mock class for stagedsync::ExecutionEngine
class MockExecutionEngine : public stagedsync::ExecutionEngine {
  public:
    static stagedsync::StageContainerFactory empty_stages_factory() {
        return [](stagedsync::SyncContext&) {
            return stagedsync::StageContainer{};
        };
    };

    MockExecutionEngine(boost::asio::any_io_executor executor, NodeSettings& ns, datastore::kvdb::RWAccess dba)
        : ExecutionEngine{
              std::move(executor),
              ns,
              db::DataModelFactory::null(),
              /* log_timer_factory = */ std::nullopt,
              empty_stages_factory(),
              std::move(dba),
          } {}
    ~MockExecutionEngine() override = default;

    MOCK_METHOD((void), open, (), (override));
    MOCK_METHOD((void), close, (), (override));

    MOCK_METHOD((void), insert_blocks, (const std::vector<std::shared_ptr<Block>>&), (override));
    MOCK_METHOD((Task<execution::api::VerificationResult>), verify_chain, (Hash), (override));
    MOCK_METHOD((bool), notify_fork_choice_update1, (Hash));
    MOCK_METHOD((bool), notify_fork_choice_update2, (Hash, Hash));
    MOCK_METHOD((bool), notify_fork_choice_update3, (Hash, Hash, Hash));
    bool notify_fork_choice_update(Hash head_block_hash,
                                   std::optional<Hash> finalized_block_hash,
                                   std::optional<Hash> safe_block_hash) override {
        if (finalized_block_hash && safe_block_hash) {
            return notify_fork_choice_update3(head_block_hash, *finalized_block_hash, *safe_block_hash);
        }
        if (finalized_block_hash) {
            return notify_fork_choice_update2(head_block_hash, *finalized_block_hash);
        }
        return notify_fork_choice_update1(head_block_hash);
    }

    MOCK_METHOD((BlockId), last_fork_choice, (), (const, override));
    MOCK_METHOD((BlockId), last_finalized_block, (), (const, override));
    MOCK_METHOD((BlockId), last_safe_block, (), (const, override));

    MOCK_METHOD((std::optional<BlockNum>), get_block_num, (Hash), (const, override));

    MOCK_METHOD((std::vector<BlockHeader>), get_last_headers, (uint64_t), (const, override));
    MOCK_METHOD((BlockNum), block_progress, (), (const, override));
};

}  // namespace silkworm::execution::api
