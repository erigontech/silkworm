// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "erigon_api.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/rpc/test_util/api_test_base.hpp>

namespace silkworm::rpc::commands {

//! Utility class to expose handle hooks publicly just for tests
class ErigonRpcApiForTest : public ErigonRpcApi {
  public:
    explicit ErigonRpcApiForTest(boost::asio::io_context& ioc, WorkerPool& workers) : ErigonRpcApi{ioc, workers} {}

    // MSVC doesn't support using access declarations properly, so explicitly forward these public accessors
    Task<void> erigon_get_block_by_timestamp(const nlohmann::json& request, std::string& reply) {
        co_return co_await ErigonRpcApi::handle_erigon_get_block_by_timestamp(request, reply);
    }
    Task<void> erigon_get_header_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
        co_return co_await ErigonRpcApi::handle_erigon_get_header_by_hash(request, reply);
    }
    Task<void> erigon_get_header_by_number(const nlohmann::json& request, nlohmann::json& reply) {
        co_return co_await ErigonRpcApi::handle_erigon_get_header_by_number(request, reply);
    }
    Task<void> erigon_get_logs_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
        co_return co_await ErigonRpcApi::handle_erigon_get_logs_by_hash(request, reply);
    }
    Task<void> erigon_forks(const nlohmann::json& request, nlohmann::json& reply) {
        co_return co_await ErigonRpcApi::handle_erigon_forks(request, reply);
    }
    Task<void> erigon_block_num(const nlohmann::json& request, nlohmann::json& reply) {
        co_return co_await ErigonRpcApi::handle_erigon_block_num(request, reply);
    }
    Task<void> erigon_node_info(const nlohmann::json& request, nlohmann::json& reply) {
        co_return co_await ErigonRpcApi::handle_erigon_node_info(request, reply);
    }
};

using ErigonRpcApiTest = test_util::JsonApiWithWorkersTestBase<ErigonRpcApiForTest>;

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(ErigonRpcApiTest, "ErigonRpcApi::handle_erigon_get_block_by_timestamp", "[rpc][erigon_api]") {
    std::string reply;
    nlohmann::json exp_rsp;

    SECTION("request params is empty: return error") {
        CHECK_NOTHROW(run<&ErigonRpcApiForTest::erigon_get_block_by_timestamp>(
            R"({
                "jsonrpc":"2.0",
                "id":1,
                "method":"erigon_getBlockByTimestamp",
                "params":[]
            })"_json,
            reply));

        std::string expected_rsp{R"({"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid erigon_getBlockByTimestamp params: []"}})"};
        CHECK(reply == expected_rsp);
    }
    SECTION("request params are incomplete: return error") {
        CHECK_NOTHROW(run<&ErigonRpcApiForTest::erigon_get_block_by_timestamp>(
            R"({
                "jsonrpc":"2.0",
                "id":1,
                "method":"erigon_getBlockByTimestamp",
                "params":["1658865942"]
            })"_json,
            reply));
        const auto expected_reply = R"({
            "jsonrpc":"2.0",
            "id":1,
            "error":{"code":100,"message":"invalid erigon_getBlockByTimestamp params: [\"1658865942\"]"}
        })"_json;
        std::string expected_rsp{R"({"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid erigon_getBlockByTimestamp params: [\"1658865942\"]"}})"};
        CHECK(reply == expected_rsp);
    }
    SECTION("request 1st param is invalid: return error") {
        CHECK_THROWS_AS(run<&ErigonRpcApiForTest::erigon_get_block_by_timestamp>(
                            R"({
                                "jsonrpc":"2.0",
                                "id":1,
                                "method":"erigon_getBlockByTimestamp",
                                "params":[true, true]
                            })"_json,
                            reply),
                        nlohmann::json::exception);
    }
    SECTION("request 2nd param is invalid: return error") {
        CHECK_THROWS_AS(run<&ErigonRpcApiForTest::erigon_get_block_by_timestamp>(
                            R"({
                                "jsonrpc":"2.0",
                                "id":1,
                                "method":"erigon_getBlockByTimestamp",
                                "params":["1658865942", "abc"]
                            })"_json,
                            reply),
                        nlohmann::json::exception);
    }
    // TODO(canepat) we need to mock silkworm::core functions properly, then we must change this check
    SECTION("request params are valid: return block w/ full transactions") {
        CHECK_THROWS_AS(run<&ErigonRpcApiForTest::erigon_get_block_by_timestamp>(
                            R"({
                                "jsonrpc":"2.0",
                                "id":1,
                                "method":"erigon_getBlockByTimestamp",
                                "params":["1658865942", true]
                            })"_json,
                            reply),
                        std::exception);
    }
}

TEST_CASE_METHOD(ErigonRpcApiTest, "ErigonRpcApi::handle_erigon_get_header_by_hash", "[rpc][erigon_api]") {
    nlohmann::json reply;

    SECTION("request params is empty: success and return error") {
        CHECK_NOTHROW(run<&ErigonRpcApiForTest::erigon_get_header_by_hash>(
            R"({
                "jsonrpc":"2.0",
                "id":1,
                "method":"erigon_getHeaderByHash",
                "params":[]
            })"_json,
            reply));
        CHECK(reply == R"({
            "jsonrpc":"2.0",
            "id":1,
            "error":{"code":-32602,"message":"invalid erigon_getHeaderByHash params: []"}
        })"_json);
    }
}

TEST_CASE_METHOD(ErigonRpcApiTest, "ErigonRpcApi::handle_erigon_get_header_by_number", "[rpc][erigon_api]") {
    nlohmann::json reply;

    SECTION("request params is empty: success and return error") {
        CHECK_NOTHROW(run<&ErigonRpcApiForTest::erigon_get_header_by_number>(
            R"({
                "jsonrpc":"2.0",
                "id":1,
                "method":"erigon_getHeaderByNumber",
                "params":[]
            })"_json,
            reply));
        CHECK(reply == R"({
            "jsonrpc":"2.0",
            "id":1,
            "error":{"code":-32602,"message":"invalid erigon_getHeaderByNumber params: []"}
        })"_json);
    }
}

TEST_CASE_METHOD(ErigonRpcApiTest, "ErigonRpcApi::handle_erigon_get_logs_by_hash", "[rpc][erigon_api]") {
    nlohmann::json reply;

    SECTION("request params is empty: success and return error") {
        CHECK_NOTHROW(run<&ErigonRpcApiForTest::erigon_get_logs_by_hash>(
            R"({
                "jsonrpc":"2.0",
                "id":1,
                "method":"erigon_getLogsByHash",
                "params":[]
            })"_json,
            reply));
        CHECK(reply == R"({
            "jsonrpc":"2.0",
            "id":1,
            "error":{"code":-32602,"message":"invalid erigon_getLogsByHash params: []"}
        })"_json);
    }
}

TEST_CASE_METHOD(ErigonRpcApiTest, "ErigonRpcApi::handle_erigon_forks", "[rpc][erigon_api]") {
    nlohmann::json reply;

    SECTION("no server connection: failure") {
        CHECK_THROWS_AS(run<&ErigonRpcApiForTest::erigon_forks>(
                            R"({
                                "jsonrpc":"2.0",
                                "id":1,
                                "method":"erigon_forks",
                                "params":[]
                            })"_json,
                            reply),
                        std::exception);
    }
}

TEST_CASE_METHOD(ErigonRpcApiTest, "ErigonRpcApi::handle_erigon_block_num", "[rpc][erigon_api]") {
    nlohmann::json reply;

#ifndef _WIN32
    SECTION("request invalid params number") {
        CHECK_NOTHROW(run<&ErigonRpcApiForTest::erigon_block_num>(
            R"({
                "jsonrpc":"2.0",
                "id":1,
                "method":"erigon_blockNumber",
                "params":["earliest", "3"]
            })"_json,
            reply));
        CHECK(reply == R"({
            "jsonrpc":"2.0",
            "id":1,
            "error":{"code":-32602,"message":"invalid erigon_blockNumber params: [\"earliest\",\"3\"]"}
        })"_json);
    }
#endif  // _WIN32

    SECTION("request earliest") {
        CHECK_THROWS_AS(run<&ErigonRpcApiForTest::erigon_block_num>(
                            R"({
                                "jsonrpc":"2.0",
                                "id":1,
                                "method":"erigon_blockNumber",
                                "params":["earliest"]
                            })"_json,
                            reply),
                        std::exception);
    }

    SECTION("request empty param") {
        CHECK_THROWS_AS(run<&ErigonRpcApiForTest::erigon_block_num>(
                            R"({
                                "jsonrpc":"2.0",
                                "id":1,
                                "method":"erigon_blockNumber",
                                "params":[]
                            })"_json,
                            reply),
                        std::exception);
    }
}

TEST_CASE_METHOD(ErigonRpcApiTest, "ErigonRpcApi::handle_erigon_node_info", "[rpc][erigon_api]") {
    nlohmann::json reply;

    SECTION("request node_info") {
        CHECK_NOTHROW(run<&ErigonRpcApiForTest::erigon_node_info>(
            R"({
                "jsonrpc":"2.0",
                "id":1,
                "method":"erigon_nodeInfo",
                "params":[]
            })"_json,
            reply));
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::commands
