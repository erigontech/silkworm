/*
   Copyright 2023 The Silkworm Authors

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
#include <optional>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/execution/api/client.hpp>

namespace silkworm::chainsync::test_util {

namespace api = execution::api;

//! \brief gMock mock class for Execution API Service.
class MockExecutionService : public execution::api::Service {
  public:
    MOCK_METHOD((Task<api::InsertionResult>), insert_blocks, (const api::Blocks&), (override));

    MOCK_METHOD((Task<api::ValidationResult>), validate_chain, (BlockId), (override));
    MOCK_METHOD((Task<api::ForkChoiceResult>), update_fork_choice, (const api::ForkChoice&), (override));

    MOCK_METHOD((Task<api::AssembleBlockResult>), assemble_block, (const api::BlockUnderConstruction&), (override));
    MOCK_METHOD((Task<api::AssembledBlockResult>), get_assembled_block, (api::PayloadId), (override));

    MOCK_METHOD((Task<std::optional<BlockHeader>>), current_header, (), (override));
    MOCK_METHOD((Task<std::optional<TotalDifficulty>>), get_td, (api::BlockNumberOrHash), (override));
    MOCK_METHOD((Task<std::optional<BlockHeader>>), get_header, (api::BlockNumberOrHash), (override));
    MOCK_METHOD((Task<std::optional<BlockBody>>), get_body, (api::BlockNumberOrHash), (override));
    MOCK_METHOD((Task<bool>), has_block, (api::BlockNumberOrHash), (override));

    MOCK_METHOD((Task<api::BlockBodies>), get_bodies_by_range, (BlockNumRange), (override));
    MOCK_METHOD((Task<api::BlockBodies>), get_bodies_by_hashes, (const api::BlockHashes&), (override));

    MOCK_METHOD((Task<bool>), is_canonical_hash, (Hash), (override));
    MOCK_METHOD((Task<std::optional<BlockNum>>), get_header_hash_number, (Hash), (override));
    MOCK_METHOD((Task<api::ForkChoice>), get_fork_choice, (), (override));

    MOCK_METHOD((Task<bool>), ready, (), (override));
    MOCK_METHOD((Task<uint64_t>), frozen_blocks, (), (override));

    MOCK_METHOD((Task<api::BlockHeaders>), get_last_headers, (uint64_t), (override));
    MOCK_METHOD((Task<BlockNum>), block_progress, (), (override));
};

//! \brief gMock mock class for Execution API Client.
struct MockExecutionClient : public execution::api::Client {
    explicit MockExecutionClient(std::shared_ptr<MockExecutionService> service)
        : service_{std::move(service)} {}

    std::shared_ptr<execution::api::Service> service() override {
        return service_;
    }

  private:
    std::shared_ptr<MockExecutionService> service_;
};

}  // namespace silkworm::chainsync::test_util
