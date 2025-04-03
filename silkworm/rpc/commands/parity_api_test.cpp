// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/rpc/test_util/api_test_database.hpp>

namespace silkworm::rpc::commands {

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(test_util::RpcApiE2ETest, "parity_getBlockReceipts: misnamed 'params' field", "[rpc][api]") {
    const nlohmann::json request = R"({"jsonrpc":"2.0","id":1,"method":"parity_getBlockReceipts","pirams":["0x0"]})";
    std::string reply;
    run<&test_util::RequestHandlerForTest::handle_request>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":1,
        "error":{"code":-32600,"message":"Invalid field: pirams"}
    })"_json);
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::commands
