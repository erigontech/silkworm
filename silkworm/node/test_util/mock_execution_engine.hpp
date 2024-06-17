/*
   Copyright 2024 The Silkworm Authors

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

#include <memory>
#include <vector>

#include <gmock/gmock.h>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/db/mdbx/mdbx.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>

namespace silkworm::execution::api {

//! \brief gMock mock class for stagedsync::ExecutionEngine
class MockExecutionEngine : public stagedsync::ExecutionEngine {
  public:
    MockExecutionEngine(boost::asio::io_context& ioc, NodeSettings& ns, db::RWAccess dba)
        : ExecutionEngine(ioc, ns, std::move(dba)) {}
    ~MockExecutionEngine() override = default;

    MOCK_METHOD((void), open, ());
    MOCK_METHOD((void), close, ());

    MOCK_METHOD((void), insert_blocks, (const std::vector<std::shared_ptr<Block>>&), (override));
    MOCK_METHOD((Task<stagedsync::VerificationResult>), verify_chain, (Hash), (override));
    MOCK_METHOD((bool), notify_fork_choice_update1, (Hash));
    MOCK_METHOD((bool), notify_fork_choice_update2, (Hash, Hash));
    MOCK_METHOD((bool), notify_fork_choice_update3, (Hash, Hash, Hash));
    bool notify_fork_choice_update(Hash head_block_hash,
                                   std::optional<Hash> finalized_block_hash,
                                   std::optional<Hash> safe_block_hash) override {
        if (finalized_block_hash && safe_block_hash) {
            return notify_fork_choice_update3(head_block_hash, *finalized_block_hash, *safe_block_hash);
        } else {
            if (finalized_block_hash) {
                return notify_fork_choice_update2(head_block_hash, *finalized_block_hash);
            } else {
                return notify_fork_choice_update1(head_block_hash);
            }
        }
        return false;
    }

    MOCK_METHOD((BlockId), last_fork_choice, (), (const, override));
    MOCK_METHOD((BlockId), last_finalized_block, (), (const, override));
    MOCK_METHOD((BlockId), last_safe_block, (), (const, override));

    MOCK_METHOD((std::optional<BlockNum>), get_block_number, (Hash), (const, override));

    MOCK_METHOD((BlockHeaders), get_last_headers, (uint64_t), (const, override));
    MOCK_METHOD((BlockNum), block_progress, (), (const, override));
};

}  // namespace silkworm::execution::api
