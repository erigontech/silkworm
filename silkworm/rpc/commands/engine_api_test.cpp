// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "engine_api.hpp"

#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <catch2/catch_test_macros.hpp>
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/db/kv/api/client.hpp>
#include <silkworm/db/test_util/mock_cursor.hpp>
#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/test_util/api_test_base.hpp>
#include <silkworm/rpc/test_util/dummy_client.hpp>
#include <silkworm/rpc/test_util/mock_back_end.hpp>
#include <silkworm/rpc/test_util/mock_execution_engine.hpp>

namespace silkworm::rpc::commands {

using db::kv::api::KeyValue;
using rpc::test::DummyClient;

class EngineRpcApiForTest : public EngineRpcApi {
  public:
    explicit EngineRpcApiForTest(boost::asio::io_context& ioc) : EngineRpcApi(ioc) {}

    using EngineRpcApi::handle_engine_exchange_capabilities;
    using EngineRpcApi::handle_engine_exchange_transition_configuration_v1;
    using EngineRpcApi::handle_engine_forkchoice_updated_v1;
    using EngineRpcApi::handle_engine_get_client_version_v1;
    using EngineRpcApi::handle_engine_get_payload_v1;
    using EngineRpcApi::handle_engine_new_payload_v1;
};

using testing::_;
using testing::InvokeWithoutArgs;

struct EngineRpcApiTest : public test_util::JsonApiTestBase<EngineRpcApiForTest> {
    EngineRpcApiTest() : test_util::JsonApiTestBase<EngineRpcApiForTest>() {
        auto local_backend = std::make_unique<test::BackEndMock>();
        add_private_service<ethbackend::BackEnd>(ioc_, std::move(local_backend));
        mock_backend = dynamic_cast<test::BackEndMock*>(must_use_private_service<ethbackend::BackEnd>(ioc_));  // NOLINT

        add_private_service<db::kv::api::Client>(ioc_, std::make_unique<DummyClient>(mock_cursor, mock_cursor_dup_sort, mock_backend));
        add_shared_service<engine::ExecutionEngine>(ioc_, mock_engine);
    }

    test::BackEndMock* mock_backend{nullptr};
    std::shared_ptr<test_util::ExecutionEngineMock> mock_engine{std::make_shared<test_util::ExecutionEngineMock>()};
    std::shared_ptr<db::test_util::MockCursor> mock_cursor{std::make_shared<db::test_util::MockCursor>()};
    std::shared_ptr<db::test_util::MockCursorDupSort> mock_cursor_dup_sort{std::make_shared<db::test_util::MockCursorDupSort>()};
};

// Exclude on MSVC due to error LNK2001: unresolved external symbol testing::Matcher<class std::basic_string_view...
// See also https://github.com/google/googletest/issues/4357
#if !defined(SILKWORM_SANITIZE) && !defined(_WIN32)
static const evmc::bytes32 kZeroHeaderHash{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};
static const silkworm::Bytes kBlockHash(32, '\0');

static const silkworm::ChainConfig kChainConfig{
    .chain_id = 11155111,
    .homestead_block = 0,
    .tangerine_whistle_block = 0,
    .spurious_dragon_block = 0,
    .byzantium_block = 0,
    .constantinople_block = 0,
    .petersburg_block = 0,
    .istanbul_block = 0,
    .berlin_block = 0,
    .london_block = 0,
    .terminal_total_difficulty = 10790000,
    .rule_set_config = protocol::EthashConfig{}};

static const silkworm::ChainConfig kChainConfigNoTerminalTotalDifficulty{
    .chain_id = 11155111,
    .homestead_block = 0,
    .tangerine_whistle_block = 0,
    .spurious_dragon_block = 0,
    .byzantium_block = 0,
    .constantinople_block = 0,
    .petersburg_block = 0,
    .istanbul_block = 0,
    .berlin_block = 0,
    .london_block = 0,
    .rule_set_config = protocol::EthashConfig{}};

TEST_CASE_METHOD(EngineRpcApiTest, "engine_exchangeCapabilities", "[silkworm][rpc][commands][engine_api]") {
    nlohmann::json reply;

    SECTION("request params is empty: return error") {
        CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_exchange_capabilities>(
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
        CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_exchange_capabilities>(
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
                    "engine_getClientVersionV1",
                    "engine_newPayloadV1",
                    "engine_newPayloadV2",
                    "engine_newPayloadV3",
                    "engine_newPayloadV4",
                    "engine_forkchoiceUpdatedV1",
                    "engine_forkchoiceUpdatedV2",
                    "engine_forkchoiceUpdatedV3",
                    "engine_getPayloadV1",
                    "engine_getPayloadV2",
                    "engine_getPayloadV3",
                    "engine_getPayloadV4",
                    "engine_getPayloadBodiesByHashV1",
                    "engine_getPayloadBodiesByRangeV1",
                    "engine_exchangeTransitionConfigurationV1"
                ]
        })"_json);
    }
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_getClientVersionV1", "[silkworm][rpc][commands][engine_api]") {
    std::string reply;

    SECTION("request params is empty: return error") {
        nlohmann::json request = R"({
            "jsonrpc":"2.0",
            "id":1,
            "method":"engine_getClientVersionV1",
            "params":[]
        })"_json;
        CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_get_client_version_v1>(request, reply));

        CHECK(reply == R"({"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid engine_getClientVersionV1 params: []"}})");
    }
    SECTION("CL client version is present and we must return our EL client version") {
        nlohmann::json request = R"({
            "jsonrpc":"2.0",
            "id":1,
            "method":"engine_getClientVersionV1",
            "params":[{
                "code":"CA",
                "name":"caplin",
                "version":"1.0.0",
                "commit":"aa00bb11"
            }]
        })"_json;
        CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_get_client_version_v1>(request, reply));

        CHECK(reply == R"({"jsonrpc":"2.0","id":1,"result":[{"code":"SW","name":"silkworm","version":"","commit":""}]})");
    }
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_getPayloadV1 OK: request is expected payload", "[silkworm][rpc][commands][engine_api]") {
    EXPECT_CALL(*mock_engine, get_payload(1, _)).WillOnce(InvokeWithoutArgs([]() -> Task<ExecutionPayloadAndValue> {
        co_return ExecutionPayloadAndValue{ExecutionPayload{.block_num = 1}, 0};
    }));

    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_getPayloadV1",
        "params":["0x0000000000000001"]
    })"_json;

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_get_payload_v1>(request, reply));

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
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_getPayloadV1 KO: invalid amount of params", "[silkworm][rpc][commands][engine_api]") {
    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_getPayloadV1",
        "params":[]
    })"_json;

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_get_payload_v1>(request, reply));

    CHECK(reply == R"({
        "error":{
            "code":-32602,
            "message":"invalid engine_getPayloadV1 params: []"
        },
        "id":1,
        "jsonrpc":"2.0" 
    })"_json);
}

TEST_CASE_METHOD(EngineRpcApiTest, "handle_engine_new_payload_v1 OK: request is expected payload status", "[silkworm][rpc][commands][engine_api]") {
    EXPECT_CALL(*mock_engine, new_payload(_, _)).WillOnce(InvokeWithoutArgs([]() -> Task<PayloadStatus> {
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

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_new_payload_v1>(request, reply));

    CHECK(reply == R"({
        "id":1,
        "jsonrpc":"2.0",
        "result": {
               "latestValidHash":"0x0000000000000000000000000000000000000000000000000000000000000040",
               "status":"INVALID",
               "validationError":"some error"
        }
    })"_json);
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_newPayloadV1 KO: invalid amount of params", "[silkworm][rpc][commands][engine_api]") {
    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_newPayloadV1",
        "params":[]
    })"_json;

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_new_payload_v1>(request, reply));

    CHECK(reply == R"({
        "error":{
            "code":-32602,
            "message":"invalid engine_newPayloadV1 params: []"
        },
        "id":1,
        "jsonrpc":"2.0" 
    })"_json);
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_forkchoiceUpdatedV1 OK: only forkchoiceState", "[silkworm][rpc][commands][engine_api]") {
    EXPECT_CALL(*mock_engine, fork_choice_updated(_, _)).WillOnce(InvokeWithoutArgs([]() -> Task<ForkChoiceUpdatedReply> {
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

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_forkchoice_updated_v1>(request, reply));

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
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_forkchoiceUpdatedV1 OK: both params", "[silkworm][rpc][commands][engine_api]") {
    EXPECT_CALL(*mock_engine, fork_choice_updated(_, _)).WillOnce(InvokeWithoutArgs([]() -> Task<ForkChoiceUpdatedReply> {
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

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_forkchoice_updated_v1>(request, reply));

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
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_forkchoiceUpdatedV1 OK: both params and null second", "[silkworm][rpc][commands][engine_api]") {
    EXPECT_CALL(*mock_engine, fork_choice_updated(_, _)).WillOnce(InvokeWithoutArgs([]() -> Task<ForkChoiceUpdatedReply> {
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

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_forkchoice_updated_v1>(request, reply));

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
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_forkchoiceUpdatedV1 KO: invalid amount of params", "[silkworm][rpc][commands][engine_api]") {
    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_forkchoiceUpdatedV1",
        "params":[]
    })"_json;

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_forkchoice_updated_v1>(request, reply));

    CHECK(reply == R"({
        "error":{
            "code":-32602,
            "message":"invalid engine_forkchoiceUpdatedV1 params: []"
        },
        "id":1,
        "jsonrpc":"2.0" 
    })"_json);
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_forkchoiceUpdatedV1 KO: empty finalized block hash", "[silkworm][rpc][commands][engine_api]") {
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

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_forkchoice_updated_v1>(request, reply));

    CHECK(reply == R"({
        "error":{
            "code":-38002,
            "message":"finalized block hash is empty"
        },
        "id":1,
        "jsonrpc":"2.0" 
    })"_json);
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_forkchoiceUpdatedv1 KO: empty safe block hash", "[silkworm][rpc][commands][engine_api]") {
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

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_forkchoice_updated_v1>(request, reply));

    CHECK(reply == R"({
        "error":{
            "code":-38002,
            "message":"safe block hash is empty"
        },
        "id":1,
        "jsonrpc":"2.0" 
    })"_json);
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_transitionConfigurationV1 OK: EL config has the same CL config", "[silkworm][rpc][commands][engine_api]") {
    const silkworm::Bytes genesis_block_hash{*silkworm::from_hex("0000000000000000000000000000000000000000000000000000000000000000")};
    const silkworm::ByteView genesis_block_key{genesis_block_hash};
    EXPECT_CALL(*mock_backend, get_block_hash_from_block_num(_))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
            co_return kZeroHeaderHash;
        }));

    EXPECT_CALL(*mock_cursor, seek_exact(genesis_block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, Bytes{string_view_to_byte_view(kChainConfig.to_json().dump())}};
    }));

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

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_exchange_transition_configuration_v1>(request, reply));

    CHECK(reply == R"({
        "id":1,
        "jsonrpc":"2.0",
        "result":{
            "terminalBlockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "terminalBlockNumber": "0x0",
            "terminalTotalDifficulty": "0xa4a470"
        }
    })"_json);
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_transitionConfigurationV1 OK: terminal block number zero if not sent", "[silkworm][rpc][commands][engine_api]") {
    EXPECT_CALL(*mock_backend, get_block_hash_from_block_num(_))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
            co_return kZeroHeaderHash;
        }));

    const silkworm::Bytes genesis_block_hash{*silkworm::from_hex("0000000000000000000000000000000000000000000000000000000000000000")};
    const silkworm::ByteView genesis_block_key{genesis_block_hash};
    EXPECT_CALL(*mock_cursor, seek_exact(genesis_block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, Bytes{string_view_to_byte_view(kChainConfig.to_json().dump())}};
    }));

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

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_exchange_transition_configuration_v1>(request, reply));

    CHECK(reply == R"({
        "id":1,
        "jsonrpc":"2.0",
        "result":{
            "terminalBlockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "terminalBlockNumber": "0x0",
            "terminalTotalDifficulty": "0xa4a470"
        }
    })"_json);
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_transitionConfigurationV1 KO: incorrect terminal total difficulty", "[silkworm][rpc][commands][engine_api]") {
    EXPECT_CALL(*mock_backend, get_block_hash_from_block_num(_))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
            co_return kZeroHeaderHash;
        }));

    const silkworm::Bytes genesis_block_hash{*silkworm::from_hex("0000000000000000000000000000000000000000000000000000000000000000")};
    const silkworm::ByteView genesis_block_key{genesis_block_hash};
    EXPECT_CALL(*mock_cursor, seek_exact(genesis_block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, Bytes{string_view_to_byte_view(kChainConfig.to_json().dump())}};
    }));

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

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_exchange_transition_configuration_v1>(request, reply));

    CHECK(reply == R"({
        "error":{
            "code":-32602,
            "message":"consensus layer terminal total difficulty does not match"
            },
            "id":1,
            "jsonrpc":"2.0"
        })"_json);
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_transitionConfigurationV1 KO: EL does not have TTD", "[silkworm][rpc][commands][engine_api]") {
    EXPECT_CALL(*mock_backend, get_block_hash_from_block_num(_))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
            co_return kZeroHeaderHash;
        }));

    const silkworm::Bytes genesis_block_hash{*silkworm::from_hex("0000000000000000000000000000000000000000000000000000000000000000")};
    const silkworm::ByteView genesis_block_key{genesis_block_hash};
    EXPECT_CALL(*mock_cursor, seek_exact(genesis_block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, Bytes{string_view_to_byte_view(kChainConfigNoTerminalTotalDifficulty.to_json().dump())}};
    }));

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

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_exchange_transition_configuration_v1>(request, reply));

    CHECK(reply == R"({
        "error":{
            "code":-32603,
            "message":"execution layer does not have terminal total difficulty"
            },
            "id":1,
            "jsonrpc":"2.0"
        })"_json);
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_transitionConfigurationV1 KO: CL sends wrong TTD", "[silkworm][rpc][commands][engine_api]") {
    EXPECT_CALL(*mock_backend, get_block_hash_from_block_num(_))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
            co_return kZeroHeaderHash;
        }));

    const silkworm::Bytes genesis_block_hash{*silkworm::from_hex("0000000000000000000000000000000000000000000000000000000000000000")};
    const silkworm::ByteView genesis_block_key{genesis_block_hash};
    EXPECT_CALL(*mock_cursor, seek_exact(genesis_block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, Bytes{string_view_to_byte_view(kChainConfig.to_json().dump())}};
    }));

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

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_exchange_transition_configuration_v1>(request, reply));

    CHECK(reply == R"({
        "error":{
            "code":-32602,
            "message":"consensus layer terminal total difficulty does not match"
            },
            "id":1,
            "jsonrpc":"2.0"
        })"_json);
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_transitionConfigurationV1 KO: CL sends wrong terminal block hash", "[silkworm][rpc][commands][engine_api]") {
    EXPECT_CALL(*mock_backend, get_block_hash_from_block_num(_))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
            co_return kZeroHeaderHash;
        }));

    const silkworm::Bytes genesis_block_hash{*silkworm::from_hex("0000000000000000000000000000000000000000000000000000000000000000")};
    const silkworm::ByteView genesis_block_key{genesis_block_hash};
    EXPECT_CALL(*mock_cursor, seek_exact(genesis_block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, Bytes{string_view_to_byte_view(kChainConfig.to_json().dump())}};
    }));

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

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_exchange_transition_configuration_v1>(request, reply));

    CHECK(reply == R"({
        "error":{
            "code":-32602,
            "message":"consensus layer terminal block hash is not zero"
            },
            "id":1,
            "jsonrpc":"2.0"
        })"_json);
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_transitionConfigurationV1 OK: no matching terminal block number", "[silkworm][rpc][commands][engine_api]") {
    EXPECT_CALL(*mock_backend, get_block_hash_from_block_num(_))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
            co_return kZeroHeaderHash;
        }));

    const silkworm::Bytes genesis_block_hash{*silkworm::from_hex("0000000000000000000000000000000000000000000000000000000000000000")};
    const silkworm::ByteView genesis_block_key{genesis_block_hash};
    EXPECT_CALL(*mock_cursor, seek_exact(genesis_block_key)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, Bytes{string_view_to_byte_view(kChainConfig.to_json().dump())}};
    }));

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

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_exchange_transition_configuration_v1>(request, reply));

    CHECK(reply == R"({
        "id":1,
        "jsonrpc":"2.0",
        "result":{
            "terminalBlockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "terminalBlockNumber": "0x0",
            "terminalTotalDifficulty": "0xa4a470"
        }
    })"_json);
}

TEST_CASE_METHOD(EngineRpcApiTest, "engine_transitionConfigurationV1 KO: incorrect params", "[silkworm][rpc][commands][engine_api]") {
    nlohmann::json reply;
    nlohmann::json request = R"({
        "jsonrpc":"2.0",
        "id":1,
        "method":"engine_transitionConfigurationV1",
        "params":[]
    })"_json;

    CHECK_NOTHROW(run<&EngineRpcApiForTest::handle_engine_exchange_transition_configuration_v1>(request, reply));

    CHECK(reply == R"({
        "error":{
            "code":-32602,
            "message":"invalid engine_exchangeTransitionConfigurationV1 params: []"
            },
            "id":1,
            "jsonrpc":"2.0"
        })"_json);
}
#endif  // !defined(SILKWORM_SANITIZE) && !defined(_WIN32)

}  // namespace silkworm::rpc::commands
