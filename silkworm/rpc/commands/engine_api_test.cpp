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

#include "engine_api.hpp"

#include <string>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch.hpp>
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/ethdb/transaction_database.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/storage/remote_chain_storage.hpp>
#include <silkworm/rpc/test/api_test_base.hpp>
#include <silkworm/rpc/test/mock_back_end.hpp>
#include <silkworm/rpc/test/mock_cursor.hpp>

namespace silkworm::rpc::commands {

namespace {
    //! This dummy transaction just gives you the same cursor over and over again.
    class DummyTransaction : public ethdb::Transaction {
      public:
        explicit DummyTransaction(std::shared_ptr<ethdb::Cursor> cursor) : cursor_(std::move(cursor)) {}

        [[nodiscard]] uint64_t view_id() const override { return 0; }

        Task<void> open() override { co_return; }

        Task<std::shared_ptr<ethdb::Cursor>> cursor(const std::string& /*table*/) override {
            co_return cursor_;
        }

        Task<std::shared_ptr<ethdb::CursorDupSort>> cursor_dup_sort(const std::string& /*table*/) override {
            co_return nullptr;
        }

        std::shared_ptr<silkworm::State> create_state(boost::asio::any_io_executor&, const core::rawdb::DatabaseReader&, const ChainStorage&, BlockNum) override {
            return nullptr;
        }

        std::shared_ptr<ChainStorage> create_storage(const core::rawdb::DatabaseReader& db_reader, ethbackend::BackEnd* backend) override {
            return std::make_shared<RemoteChainStorage>(db_reader, backend);
        }

        Task<void> close() override { co_return; }

      private:
        std::shared_ptr<ethdb::Cursor> cursor_;
    };

    //! This dummy database acts as a factory for dummy transactions using the same cursor.
    class DummyDatabase : public ethdb::Database {
      public:
        explicit DummyDatabase(std::shared_ptr<ethdb::Cursor> cursor) : cursor_(std::move(cursor)) {}

        Task<std::unique_ptr<ethdb::Transaction>> begin() override {
            co_return std::make_unique<DummyTransaction>(cursor_);
        }

      private:
        std::shared_ptr<ethdb::Cursor> cursor_;
    };

}  // namespace

class EngineRpcApi_ForTest : public EngineRpcApi {
  public:
    EngineRpcApi_ForTest(ethdb::Database* database, ethbackend::BackEnd* backend)
        : EngineRpcApi(database, backend) {}
    explicit EngineRpcApi_ForTest(boost::asio::io_context& io_context) : EngineRpcApi(io_context) {}

    using EngineRpcApi::handle_engine_exchange_capabilities;
    using EngineRpcApi::handle_engine_exchange_transition_configuration_v1;
    using EngineRpcApi::handle_engine_forkchoice_updated_v1;
    using EngineRpcApi::handle_engine_get_payload_v1;
    using EngineRpcApi::handle_engine_new_payload_v1;
};

using testing::InvokeWithoutArgs;

static silkworm::Bytes kBlockHash(32, '\0');
const silkworm::ChainConfig kChainConfig{
    .chain_id = 5,
    .homestead_block = 0,
    .tangerine_whistle_block = 0,
    .spurious_dragon_block = 0,
    .byzantium_block = 0,
    .constantinople_block = 0,
    .petersburg_block = 0,
    .istanbul_block = 1561651,
    .berlin_block = 4460644,
    .london_block = 5062605,
    .terminal_total_difficulty = 10790000,
    .rule_set_config = protocol::CliqueConfig{}};

const silkworm::ChainConfig kChainConfigNoTerminalTotalDifficulty{
    .chain_id = 5,
    .homestead_block = 0,
    .tangerine_whistle_block = 0,
    .spurious_dragon_block = 0,
    .byzantium_block = 0,
    .constantinople_block = 0,
    .petersburg_block = 0,
    .istanbul_block = 1561651,
    .berlin_block = 4460644,
    .london_block = 5062605,
    .rule_set_config = protocol::CliqueConfig{}};

using EngineRpcApiTest = test::JsonApiTestBase<EngineRpcApi_ForTest>;

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(EngineRpcApiTest, "EngineRpcApi::handle_engine_exchange_capabilities", "[silkworm][rpc][commands][engine_api]") {
    nlohmann::json reply;

    SECTION("request params is empty: return error") {
        CHECK_NOTHROW(run<&EngineRpcApi_ForTest::handle_engine_exchange_capabilities>(
            R"({
                "jsonrpc":"2.0",
                "id":1,
                "method":"engine_exchangeCapabilities",
                "params":[]
            })"_json,
            reply));
        CHECK(reply == R"({
            "jsonrpc":"2.0",
            "id":1,
            "error":{"code":-32602,"message":"invalid engine_exchangeCapabilities params: []"}
        })"_json);
    }
    SECTION("no CL capabilities is OK and we must return our EL capabilities") {
        CHECK_NOTHROW(run<&EngineRpcApi_ForTest::handle_engine_exchange_capabilities>(
            R"({
                "jsonrpc":"2.0",
                "id":1,
                "method":"engine_exchangeCapabilities",
                "params":[[]]
            })"_json,
            reply));
        CHECK(reply == R"({
                "id":1,
                "jsonrpc":"2.0",
                "result":[
                    "engine_newPayloadV1",
                    "engine_newPayloadV2",
                    "engine_forkchoiceUpdatedV1",
                    "engine_forkchoiceUpdatedV2",
                    "engine_getPayloadV1",
                    "engine_getPayloadV2",
                    "engine_getPayloadBodiesByHashV1",
                    "engine_getPayloadBodiesByRangeV1",
                    "engine_exchangeTransitionConfigurationV1"
                ]
        })"_json);
    }
}

TEST_CASE("handle_engine_get_payload_v1 succeeds if request is expected payload", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    const auto backend = std::make_unique<test::BackEndMock>();
    EXPECT_CALL(*backend, engine_get_payload(1)).WillOnce(InvokeWithoutArgs([]() -> Task<ExecutionPayloadAndValue> {
        co_return ExecutionPayloadAndValue{ExecutionPayload{.number = 1}, 0};
    }));

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_getPayloadV1",
        "params":["0x0000000000000001"]
    })"_json;

    ClientContextPool cp{1};
    cp.start();
    std::unique_ptr<ethdb::Database> database;
    // Initialise components
    EngineRpcApi_ForTest rpc(database.get(), backend.get());

    // spawn routine
    auto result{boost::asio::co_spawn(
        cp.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_get_payload_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();

    CHECK(reply == R"({
        "id":1,
        "jsonrpc":"2.0",
        "result":{
            "baseFeePerGas":"0x0",
            "blockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "blockNumber":"0x1",
            "extraData":"0x",
            "gasLimit":"0x0",
            "gasUsed":"0x0",
            "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "prevRandao": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "receiptsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "stateRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "feeRecipient":"0x0000000000000000000000000000000000000000",
            "timestamp":"0x0",
            "transactions":null
         }
    })"_json);

    cp.stop();
    cp.join();
}

TEST_CASE("handle_engine_get_payload_v1 fails with invalid amount of params", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_getPayloadV1",
        "params":[]
    })"_json;
    // Initialize context pool
    ClientContextPool cp{1};
    cp.start();
    // Initialise components
    const auto backend = std::make_unique<test::BackEndMock>();
    std::unique_ptr<ethdb::Database> database;
    EngineRpcApi_ForTest rpc(database.get(), backend.get());

    // spawn routine
    auto result{boost::asio::co_spawn(
        cp.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_get_payload_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();

    CHECK(reply == R"({
        "error":{
            "code":-32602,
            "message":"invalid engine_getPayloadV1 params: []"
        },
        "id":1,
        "jsonrpc":"2.0" 
    })"_json);

    cp.stop();
    cp.join();
}

TEST_CASE("handle_engine_new_payload_v1 succeeds if request is expected payload status", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    const auto backend = std::make_unique<test::BackEndMock>();
    EXPECT_CALL(*backend, engine_new_payload(testing::_)).WillOnce(InvokeWithoutArgs([]() -> Task<PayloadStatus> {
        co_return PayloadStatus{
            .status = "INVALID",
            .latest_valid_hash = 0x0000000000000000000000000000000000000000000000000000000000000040_bytes32,
            .validation_error = "some error"};
    }));

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_newPayloadV1",
        "params":[{
            "parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
            "feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45",
            "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000001",
            "blockNumber":"0x1",
            "gasLimit":"0x1c9c380",
            "gasUsed":"0x0",
            "timestamp":"0x5",
            "extraData":"0x",
            "baseFeePerGas":"0x7",
            "blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
            "transactions":["0xf92ebdeab45d368f6354e8c5a8ac586c"]
        }]
    })"_json;
    // Initialize context pool
    ClientContextPool cp{1};
    cp.start();
    std::unique_ptr<ethdb::Database> database;
    // Initialise components
    EngineRpcApi_ForTest rpc(database.get(), backend.get());

    // spawn routine
    auto result{boost::asio::co_spawn(
        cp.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_new_payload_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();

    CHECK(reply == R"({
        "id":1,
        "jsonrpc":"2.0",
        "result": {
               "latestValidHash":"0x0000000000000000000000000000000000000000000000000000000000000040",
               "status":"INVALID",
               "validationError":"some error"
        }
    })"_json);

    cp.stop();
    cp.join();
}

TEST_CASE("handle_engine_new_payload_v1 fails with invalid amount of params", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_newPayloadV1",
        "params":[]
    })"_json;
    // Initialize context pool
    ClientContextPool cp{1};
    cp.start();
    // Initialise components
    const auto backend = std::make_unique<test::BackEndMock>();
    std::unique_ptr<ethdb::Database> database;
    EngineRpcApi_ForTest rpc(database.get(), backend.get());

    // spawn routine
    auto result{boost::asio::co_spawn(
        cp.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_new_payload_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();

    CHECK(reply == R"({
        "error":{
            "code":-32602,
            "message":"invalid engine_newPayloadV1 params: []"
        },
        "id":1,
        "jsonrpc":"2.0" 
    })"_json);

    cp.stop();
    cp.join();
}

TEST_CASE("handle_engine_forkchoice_updated_v1 succeeds only with forkchoiceState", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    const auto backend = std::make_unique<test::BackEndMock>();
    EXPECT_CALL(*backend, engine_forkchoice_updated(testing::_)).WillOnce(InvokeWithoutArgs([]() -> Task<ForkChoiceUpdatedReply> {
        co_return ForkChoiceUpdatedReply{
            .payload_status = PayloadStatus{
                .status = "INVALID",
                .latest_valid_hash = 0x0000000000000000000000000000000000000000000000000000000000000040_bytes32,
                .validation_error = "some error"},
            .payload_id = std::nullopt};
    }));

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_forkchoiceUpdatedV1",
        "params":[
            {
                "headBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                "safeBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                "finalizedBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a"
            }
        ]
    })"_json;
    // Initialize context pool
    ClientContextPool cp{1};
    cp.start();
    // Initialise components
    std::unique_ptr<ethdb::Database> database;
    EngineRpcApi_ForTest rpc(database.get(), backend.get());

    // spawn routine
    auto result{boost::asio::co_spawn(
        cp.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_forkchoice_updated_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();
    CHECK(reply == R"({
        "jsonrpc":"2.0",
        "id":1,
        "result": {
           "payloadStatus":{
               "latestValidHash":"0x0000000000000000000000000000000000000000000000000000000000000040",
               "status":"INVALID",
               "validationError":"some error"
           }
        }
    })"_json);
    cp.stop();
    cp.join();
}

TEST_CASE("handle_engine_forkchoice_updated_v1 succeeds with both params", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    const auto backend = std::make_unique<test::BackEndMock>();
    EXPECT_CALL(*backend, engine_forkchoice_updated(testing::_)).WillOnce(InvokeWithoutArgs([]() -> Task<ForkChoiceUpdatedReply> {
        co_return ForkChoiceUpdatedReply{
            .payload_status = PayloadStatus{
                .status = "INVALID",
                .latest_valid_hash = 0x0000000000000000000000000000000000000000000000000000000000000040_bytes32,
                .validation_error = "some error"},
            .payload_id = std::nullopt};
    }));

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_forkchoiceUpdatedV1",
        "params":[
            {
                "headBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                "safeBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                "finalizedBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a"
            },
            {
                "timestamp":"0x1",
                "prevRandao":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                "suggestedFeeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
            }
        ]
    })"_json;
    // Initialize context pool
    ClientContextPool cp{1};
    cp.start();
    // Initialise components
    std::unique_ptr<ethdb::Database> database;
    EngineRpcApi_ForTest rpc(database.get(), backend.get());

    // spawn routine
    auto result{boost::asio::co_spawn(
        cp.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_forkchoice_updated_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();
    CHECK(reply == R"({
        "jsonrpc":"2.0",
        "id":1,
        "result": {
           "payloadStatus":{
               "latestValidHash":"0x0000000000000000000000000000000000000000000000000000000000000040",
               "status":"INVALID",
               "validationError":"some error"
           }
        }
    })"_json);
    cp.stop();
    cp.join();
}

TEST_CASE("handle_engine_forkchoice_updated_v1 succeeds with both params and second set to null", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    const auto backend = std::make_unique<test::BackEndMock>();
    EXPECT_CALL(*backend, engine_forkchoice_updated(testing::_)).WillOnce(InvokeWithoutArgs([]() -> Task<ForkChoiceUpdatedReply> {
        co_return ForkChoiceUpdatedReply{
            .payload_status = PayloadStatus{
                .status = "INVALID",
                .latest_valid_hash = 0x0000000000000000000000000000000000000000000000000000000000000040_bytes32,
                .validation_error = "some error"},
            .payload_id = std::nullopt};
    }));

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_forkchoiceUpdatedV1",
        "params":[
            {
                "headBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                "safeBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                "finalizedBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a"
            },
            null
        ]
    })"_json;
    // Initialize context pool
    ClientContextPool cp{1};
    cp.start();
    // Initialise components
    std::unique_ptr<ethdb::Database> database;
    EngineRpcApi_ForTest rpc(database.get(), backend.get());

    // spawn routine
    auto result{boost::asio::co_spawn(
        cp.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_forkchoice_updated_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();
    CHECK(reply == R"({
        "jsonrpc":"2.0",
        "id":1,
        "result": {
           "payloadStatus":{
               "latestValidHash":"0x0000000000000000000000000000000000000000000000000000000000000040",
               "status":"INVALID",
               "validationError":"some error"
           }
        }
    })"_json);
    cp.stop();
    cp.join();
}

TEST_CASE("handle_engine_forkchoice_updated_v1 fails with invalid amount of params", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_forkchoiceUpdatedV1",
        "params":[]
    })"_json;
    // Initialize context pool
    ClientContextPool cp{1};
    cp.start();
    // Initialise components
    const auto backend = std::make_unique<test::BackEndMock>();
    std::unique_ptr<ethdb::Database> database;
    EngineRpcApi_ForTest rpc(database.get(), backend.get());

    // spawn routine
    auto result{boost::asio::co_spawn(
        cp.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_forkchoice_updated_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();

    CHECK(reply == R"({
        "error":{
            "code":-32602,
            "message":"invalid engine_forkchoiceUpdatedV1 params: []"
        },
        "id":1,
        "jsonrpc":"2.0" 
    })"_json);

    cp.stop();
    cp.join();
}

TEST_CASE("handle_engine_forkchoice_updated_v1 fails with empty finalized block hash", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    const auto backend = std::make_unique<test::BackEndMock>();
    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_forkchoiceUpdatedV1",
        "params":[
            {
                "headBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                "safeBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                "finalizedBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000000"
            }
        ]
    })"_json;
    // Initialize context pool
    ClientContextPool cp{1};
    cp.start();
    // Initialise components
    std::unique_ptr<ethdb::Database> database;
    EngineRpcApi_ForTest rpc(database.get(), backend.get());

    // spawn routine
    auto result{boost::asio::co_spawn(
        cp.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_forkchoice_updated_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();
    CHECK(reply == R"({
        "error":{
            "code":-38002,
            "message":"finalized block hash is empty"
        },
        "id":1,
        "jsonrpc":"2.0" 
    })"_json);
    cp.stop();
    cp.join();
}

TEST_CASE("handle_engine_forkchoice_updated_v1 fails with empty safe block hash", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    const auto backend = std::make_unique<test::BackEndMock>();
    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_forkchoiceUpdatedv1",
        "params":[
            {
                "headBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                "safeBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
                "finalizedBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a"
            }
        ]
    })"_json;
    // Initialize context pool
    ClientContextPool cp{1};
    cp.start();
    // Initialise components
    std::unique_ptr<ethdb::Database> database;
    EngineRpcApi_ForTest rpc(database.get(), backend.get());

    // spawn routine
    auto result{boost::asio::co_spawn(
        cp.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_forkchoice_updated_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();
    CHECK(reply == R"({
        "error":{
            "code":-38002,
            "message":"safe block hash is empty"
        },
        "id":1,
        "jsonrpc":"2.0" 
    })"_json);
    cp.stop();
    cp.join();
}

TEST_CASE("handle_engine_transition_configuration_v1 succeeds if EL configurations has the same request configuration", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    ClientContextPool context_pool{1};
    context_pool.start();

    std::shared_ptr<test::MockCursor> mock_cursor = std::make_shared<test::MockCursor>();

    const silkworm::Bytes block_number{*silkworm::from_hex("0000000000000000")};
    const silkworm::ByteView block_key{block_number};
    EXPECT_CALL(*mock_cursor, seek_exact(block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, kBlockHash};
    }));

    const silkworm::Bytes genesis_block_hash{*silkworm::from_hex("0000000000000000000000000000000000000000000000000000000000000000")};
    const silkworm::ByteView genesis_block_key{genesis_block_hash};
    EXPECT_CALL(*mock_cursor, seek_exact(genesis_block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, Bytes{byte_view_of_string(kChainConfig.to_json().dump())}};
    }));

    std::unique_ptr<ethdb::Database> database_ptr = std::make_unique<DummyDatabase>(mock_cursor);
    std::unique_ptr<ethbackend::BackEnd> backend;
    EngineRpcApi_ForTest rpc(database_ptr.get(), backend.get());

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_transitionConfigurationV1",
        "params":[{
            "terminalTotalDifficulty":"0xa4a470",
            "terminalBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000000_bytes32",
            "terminalBlockNumber":"0x0"
        }]
    })"_json;

    auto result{boost::asio::co_spawn(
        context_pool.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_exchange_transition_configuration_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();

    CHECK(reply == R"({
        "id":1,
        "jsonrpc":"2.0",
        "result":{
            "terminalBlockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "terminalBlockNumber": "0x0",
            "terminalTotalDifficulty": "0xa4a470"
        }
    })"_json);

    context_pool.stop();
    context_pool.join();
}

TEST_CASE("handle_engine_transition_configuration_v1 succeeds and default terminal block number to zero if chain config doesn't specify it", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    ClientContextPool context_pool{1};
    context_pool.start();

    std::shared_ptr<test::MockCursor> mock_cursor = std::make_shared<test::MockCursor>();

    const silkworm::Bytes block_number{*silkworm::from_hex("0000000000000000")};
    const silkworm::ByteView block_key{block_number};
    EXPECT_CALL(*mock_cursor, seek_exact(block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, kBlockHash};
    }));

    const silkworm::Bytes genesis_block_hash{*silkworm::from_hex("0000000000000000000000000000000000000000000000000000000000000000")};
    const silkworm::ByteView genesis_block_key{genesis_block_hash};
    EXPECT_CALL(*mock_cursor, seek_exact(genesis_block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, Bytes{byte_view_of_string(kChainConfig.to_json().dump())}};
    }));

    std::unique_ptr<ethdb::Database> database_ptr = std::make_unique<DummyDatabase>(mock_cursor);
    std::unique_ptr<ethbackend::BackEnd> backend;
    EngineRpcApi_ForTest rpc(database_ptr.get(), backend.get());

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_transitionConfigurationV1",
        "params":[{
            "terminalTotalDifficulty":"0xa4a470",
            "terminalBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
            "terminalBlockNumber":"0x0"
        }]
    })"_json;

    auto result{boost::asio::co_spawn(
        context_pool.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_exchange_transition_configuration_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();

    CHECK(reply == R"({
        "id":1,
        "jsonrpc":"2.0",
        "result":{
            "terminalBlockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "terminalBlockNumber": "0x0",
            "terminalTotalDifficulty": "0xa4a470"
        }
    })"_json);

    context_pool.stop();
    context_pool.join();
}

TEST_CASE("handle_engine_transition_configuration_v1 fails if incorrect terminal total difficulty", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    ClientContextPool context_pool{1};
    context_pool.start();

    std::shared_ptr<test::MockCursor> mock_cursor = std::make_shared<test::MockCursor>();

    const silkworm::Bytes block_number{*silkworm::from_hex("0000000000000000")};
    const silkworm::ByteView block_key{block_number};
    EXPECT_CALL(*mock_cursor, seek_exact(block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, kBlockHash};
    }));

    const silkworm::Bytes genesis_block_hash{*silkworm::from_hex("0000000000000000000000000000000000000000000000000000000000000000")};
    const silkworm::ByteView genesis_block_key{genesis_block_hash};
    EXPECT_CALL(*mock_cursor, seek_exact(genesis_block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, Bytes{byte_view_of_string(kChainConfig.to_json().dump())}};
    }));

    std::unique_ptr<ethdb::Database> database_ptr = std::make_unique<DummyDatabase>(mock_cursor);
    std::unique_ptr<ethbackend::BackEnd> backend;
    EngineRpcApi_ForTest rpc(database_ptr.get(), backend.get());

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_transitionConfigurationV1",
        "params":[{
            "terminalTotalDifficulty":"0xf4242",
            "terminalBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
            "terminalBlockNumber":"0x0"
        }]
    })"_json;

    auto result{boost::asio::co_spawn(
        context_pool.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_exchange_transition_configuration_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();

    CHECK(reply == R"({
        "error":{
            "code":-32602,
            "message":"consensus layer terminal total difficulty does not match"
            },
            "id":1,
            "jsonrpc":"2.0"
        })"_json);
    context_pool.stop();
    context_pool.join();
}

TEST_CASE("handle_engine_transition_configuration_v1 fails if execution layer does not have terminal total difficulty", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    ClientContextPool context_pool{1};
    context_pool.start();

    std::shared_ptr<test::MockCursor> mock_cursor = std::make_shared<test::MockCursor>();

    const silkworm::Bytes block_number{*silkworm::from_hex("0000000000000000")};
    const silkworm::ByteView block_key{block_number};
    EXPECT_CALL(*mock_cursor, seek_exact(block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, kBlockHash};
    }));

    const silkworm::Bytes genesis_block_hash{*silkworm::from_hex("0000000000000000000000000000000000000000000000000000000000000000")};
    const silkworm::ByteView genesis_block_key{genesis_block_hash};
    EXPECT_CALL(*mock_cursor, seek_exact(genesis_block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, Bytes{byte_view_of_string(kChainConfigNoTerminalTotalDifficulty.to_json().dump())}};
    }));

    std::unique_ptr<ethdb::Database> database_ptr = std::make_unique<DummyDatabase>(mock_cursor);
    std::unique_ptr<ethbackend::BackEnd> backend;
    EngineRpcApi_ForTest rpc(database_ptr.get(), backend.get());

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_transitionConfigurationV1",
        "params":[{
            "terminalTotalDifficulty":"0xf4240",
            "terminalBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
            "terminalBlockNumber":"0x0"
        }]
    })"_json;

    auto result{boost::asio::co_spawn(
        context_pool.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_exchange_transition_configuration_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();

    CHECK(reply == R"({
        "error":{
            "code":-32603,
            "message":"execution layer does not have terminal total difficulty"
            },
            "id":1,
            "jsonrpc":"2.0"
        })"_json);
    context_pool.stop();
    context_pool.join();
}

TEST_CASE("handle_engine_transition_configuration_v1 fails if consensus layer sends wrong terminal total difficulty", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    ClientContextPool context_pool{1};
    context_pool.start();

    std::shared_ptr<test::MockCursor> mock_cursor = std::make_shared<test::MockCursor>();

    const silkworm::Bytes block_number{*silkworm::from_hex("0000000000000000")};
    const silkworm::ByteView block_key{block_number};
    EXPECT_CALL(*mock_cursor, seek_exact(block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, kBlockHash};
    }));

    const silkworm::Bytes genesis_block_hash{*silkworm::from_hex("0000000000000000000000000000000000000000000000000000000000000000")};
    const silkworm::ByteView genesis_block_key{genesis_block_hash};
    EXPECT_CALL(*mock_cursor, seek_exact(genesis_block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, Bytes{byte_view_of_string(kChainConfig.to_json().dump())}};
    }));

    std::unique_ptr<ethdb::Database> database_ptr = std::make_unique<DummyDatabase>(mock_cursor);
    std::unique_ptr<ethbackend::BackEnd> backend;
    EngineRpcApi_ForTest rpc(database_ptr.get(), backend.get());

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_transitionConfigurationV1",
        "params":[{
            "terminalTotalDifficulty":"0x0",
            "terminalBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
            "terminalBlockNumber":"0x0"
        }]
    })"_json;

    auto result{boost::asio::co_spawn(
        context_pool.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_exchange_transition_configuration_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();

    CHECK(reply == R"({
        "error":{
            "code":-32602,
            "message":"consensus layer terminal total difficulty does not match"
            },
            "id":1,
            "jsonrpc":"2.0"
        })"_json);
    context_pool.stop();
    context_pool.join();
}

TEST_CASE("handle_engine_transition_configuration_v1 fails if consensus layer sends wrong terminal block hash", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    ClientContextPool context_pool{1};
    context_pool.start();

    std::shared_ptr<test::MockCursor> mock_cursor = std::make_shared<test::MockCursor>();

    const silkworm::Bytes block_number{*silkworm::from_hex("0000000000000000")};
    const silkworm::ByteView block_key{block_number};
    EXPECT_CALL(*mock_cursor, seek_exact(block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, kBlockHash};
    }));

    const silkworm::Bytes genesis_block_hash{*silkworm::from_hex("0000000000000000000000000000000000000000000000000000000000000000")};
    const silkworm::ByteView genesis_block_key{genesis_block_hash};
    EXPECT_CALL(*mock_cursor, seek_exact(genesis_block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, Bytes{byte_view_of_string(kChainConfig.to_json().dump())}};
    }));

    std::unique_ptr<ethdb::Database> database_ptr = std::make_unique<DummyDatabase>(mock_cursor);
    std::unique_ptr<ethbackend::BackEnd> backend;
    EngineRpcApi_ForTest rpc(database_ptr.get(), backend.get());

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_transitionConfigurationV1",
        "params":[{
            "terminalTotalDifficulty":"0xa4a470",
            "terminalBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
            "terminalBlockNumber":"0x0"
        }]
    })"_json;

    auto result{boost::asio::co_spawn(
        context_pool.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_exchange_transition_configuration_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();

    CHECK(reply == R"({
        "error":{
            "code":-32602,
            "message":"consensus layer terminal block hash is not zero"
            },
            "id":1,
            "jsonrpc":"2.0"
        })"_json);
    context_pool.stop();
    context_pool.join();
}

TEST_CASE("handle_engine_transition_configuration_v1 succeeds w/o matching terminal block number", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    ClientContextPool context_pool{1};
    context_pool.start();

    std::shared_ptr<test::MockCursor> mock_cursor = std::make_shared<test::MockCursor>();

    const silkworm::Bytes block_number{*silkworm::from_hex("0000000000000000")};
    const silkworm::ByteView block_key{block_number};
    EXPECT_CALL(*mock_cursor, seek_exact(block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, kBlockHash};
    }));

    const silkworm::Bytes genesis_block_hash{*silkworm::from_hex("0000000000000000000000000000000000000000000000000000000000000000")};
    const silkworm::ByteView genesis_block_key{genesis_block_hash};
    EXPECT_CALL(*mock_cursor, seek_exact(genesis_block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, Bytes{byte_view_of_string(kChainConfig.to_json().dump())}};
    }));

    std::unique_ptr<ethdb::Database> database_ptr = std::make_unique<DummyDatabase>(mock_cursor);
    std::unique_ptr<ethbackend::BackEnd> backend;
    EngineRpcApi_ForTest rpc(database_ptr.get(), backend.get());

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_transitionConfigurationV1",
        "params":[{
            "terminalTotalDifficulty":"0xa4a470",
            "terminalBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
            "terminalBlockNumber":"0x1"
        }]
    })"_json;

    auto result{boost::asio::co_spawn(
        context_pool.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_exchange_transition_configuration_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();

    CHECK(reply == R"({
        "id":1,
        "jsonrpc":"2.0",
        "result":{
            "terminalBlockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "terminalBlockNumber": "0x0",
            "terminalTotalDifficulty": "0xa4a470"
        }
    })"_json);
    context_pool.stop();
    context_pool.join();
}

TEST_CASE("handle_engine_transition_configuration_v1 fails if incorrect params", "[silkworm][rpc][commands][engine_api]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    ClientContextPool context_pool{1};
    context_pool.start();

    std::shared_ptr<test::MockCursor> mock_cursor = std::make_shared<test::MockCursor>();

    std::unique_ptr<ethdb::Database> database_ptr = std::make_unique<DummyDatabase>(mock_cursor);
    std::unique_ptr<ethbackend::BackEnd> backend;
    EngineRpcApi_ForTest rpc(database_ptr.get(), backend.get());

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_transitionConfigurationV1",
        "params":[]
    })"_json;

    auto result{boost::asio::co_spawn(
        context_pool.next_io_context(), [&rpc, &reply, &request]() {
            return rpc.handle_engine_exchange_transition_configuration_v1(
                request,
                reply);
        },
        boost::asio::use_future)};
    result.get();

    CHECK(reply == R"({
        "error":{
            "code":-32602,
            "message":"invalid engine_exchangeTransitionConfigurationV1 params: []"
            },
            "id":1,
            "jsonrpc":"2.0"
        })"_json);
    context_pool.stop();
    context_pool.join();
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::commands
