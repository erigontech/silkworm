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
#include <vector>

#include <gmock/gmock.h>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/sync/block_exchange.hpp>
#include <silkworm/sync/messages/message.hpp>
#include <silkworm/sync/sentry_client.hpp>

namespace silkworm::chainsync::test_util {

//! \brief MockBlockExchange is the gMock mock class for BlockExchange.
class MockBlockExchange : public IBlockExchange {
  public:
    ~MockBlockExchange() override = default;

    MOCK_METHOD((void), initial_state, (std::vector<BlockHeader>), (override));

    MOCK_METHOD((void), download_blocks, (BlockNum, TargetTracking), (override));
    MOCK_METHOD((void), new_target_block, (std::shared_ptr<Block>), (override));
    MOCK_METHOD((void), stop_downloading, (), (override));

    MOCK_METHOD((ResultQueue&), result_queue, (), (override));

    MOCK_METHOD((bool), in_sync, (), (const, override));
    MOCK_METHOD((BlockNum), current_block_num, (), (const, override));

    MOCK_METHOD((void), accept, (std::shared_ptr<Message>), (override));
    MOCK_METHOD((void), execution_loop, (), (override));

    MOCK_METHOD((const ChainConfig&), chain_config, (), (const, override));
    MOCK_METHOD((SentryClient&), sentry, (), (const, override));
};

}  // namespace silkworm::chainsync::test_util
