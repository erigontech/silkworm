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

#include <optional>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/node/stagedsync/client.hpp>
#include <silkworm/node/stagedsync/types.hpp>

namespace silkworm::chainsync::test_util {

//! \brief MockBlockExchange is the gMock mock class for execution::Client.
class MockClient : public execution::Client {
  public:
    MOCK_METHOD((boost::asio::io_context&), get_executor, (), (override));

    MOCK_METHOD((Task<void>), insert_headers, (const execution::BlockVector&), (override));
    MOCK_METHOD((Task<void>), insert_bodies, (const execution::BlockVector&), (override));
    MOCK_METHOD((Task<void>), insert_blocks, (const execution::BlockVector&), (override));

    MOCK_METHOD((Task<execution::ValidationResult>), validate_chain, (Hash), (override));

    MOCK_METHOD((Task<execution::ForkChoiceApplication>), update_fork_choice, (Hash, std::optional<Hash>), (override));

    MOCK_METHOD((Task<BlockNum>), block_progress, (), (override));
    MOCK_METHOD((Task<BlockId>), last_fork_choice, (), (override));

    MOCK_METHOD((Task<std::optional<BlockHeader>>), get_header, (Hash), (override));
    MOCK_METHOD((Task<std::optional<BlockHeader>>), get_header, (BlockNum, Hash), (override));
    MOCK_METHOD((Task<std::optional<BlockBody>>), get_body, (Hash), (override));
    MOCK_METHOD((Task<std::optional<BlockBody>>), get_body, (BlockNum), (override));

    MOCK_METHOD((Task<bool>), is_canonical, (Hash), (override));
    MOCK_METHOD((Task<std::optional<BlockNum>>), get_block_num, (Hash), (override));

    MOCK_METHOD((Task<std::vector<BlockHeader>>), get_last_headers, (BlockNum), (override));
    MOCK_METHOD((Task<std::optional<TotalDifficulty>>), get_header_td, (Hash, std::optional<BlockNum>), (override));
};

}  // namespace silkworm::chainsync::test_util
