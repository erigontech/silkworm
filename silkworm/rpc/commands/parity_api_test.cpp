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

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/rpc/test_util/api_test_database.hpp>

namespace silkworm::rpc::commands {

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(test_util::RpcApiE2ETest, "parity_getBlockReceipts: misnamed 'params' field", "[rpc][api]") {
    const auto request = R"({"jsonrpc":"2.0","id":1,"method":"parity_getBlockReceipts","pirams":["0x0"]})";
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
