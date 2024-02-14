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

#include "sync_pos.hpp"

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <catch2/catch.hpp>
#include <gmock/gmock.h>

#include <silkworm/node/stagedsync/client.hpp>
#include <silkworm/rpc/test/context_test_base.hpp>
#include <silkworm/sync/block_exchange.hpp>
#include <silkworm/sync/sentry_client.hpp>

#include "test_util/mock_block_exchange.hpp"
#include "test_util/mock_execution_client.hpp"

namespace silkworm::chainsync {

struct PoSSyncTest : public rpc::test::ContextTestBase {
    SentryClient sentry_client_{io_context_.get_executor(), nullptr};  // TODO(canepat) mock
    mdbx::env_managed chaindata_env_{};
    db::ROAccess db_access_{chaindata_env_};
    test_util::MockBlockExchange block_exchange_{sentry_client_, db_access_, kGoerliConfig};
    test_util::MockClient execution_client_;
    PoSSync sync_{block_exchange_, execution_client_};
};

Task<void> sleep(std::chrono::milliseconds duration) {
    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    timer.expires_after(duration);
    co_await timer.async_wait(boost::asio::use_awaitable);
}

TEST_CASE_METHOD(PoSSyncTest, "PoSSync::new_payload timeout") {
    using namespace std::chrono_literals;
    using testing::_;
    using testing::InvokeWithoutArgs;

    rpc::ExecutionPayload payload{
        .number = 1,
        .timestamp = 0x05,
        .gas_limit = 0x1c9c380,
        .gas_used = 0x0,
        .suggested_fee_recipient = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address,
        .state_root = 0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45_bytes32,
        .receipts_root = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32,
        .parent_hash = 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32,
        .block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
        .prev_randao = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32,
        .base_fee = 0x7,
    };

    EXPECT_CALL(execution_client_, get_header(payload.number - 1, Hash{payload.parent_hash}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<BlockHeader>> {
            co_return BlockHeader{};
        }));
    EXPECT_CALL(execution_client_, get_header_td(Hash{payload.parent_hash}, std::make_optional(payload.number - 1)))
        .WillOnce(InvokeWithoutArgs([&]() -> Task<std::optional<TotalDifficulty>> {
            co_return kGoerliConfig.terminal_total_difficulty;
        }));
    EXPECT_CALL(execution_client_, insert_blocks(_))
        .WillOnce(InvokeWithoutArgs([]() -> Task<void> { co_return; }));
    EXPECT_CALL(execution_client_, get_block_num(Hash{payload.block_hash}))
        .WillOnce(InvokeWithoutArgs([&]() -> Task<std::optional<BlockNum>> { co_return payload.number; }));
    EXPECT_CALL(execution_client_, validate_chain(Hash{payload.block_hash}))
        .WillOnce(InvokeWithoutArgs([&]() -> Task<execution::ValidationResult> {
            co_await sleep(1h);  // simulate exaggeratedly long-running task
            co_return execution::ValidChain{};
        }));

    CHECK(spawn_and_wait(sync_.new_payload(payload, 1ms)).status == rpc::PayloadStatus::kSyncing);
}

}  // namespace silkworm::chainsync
