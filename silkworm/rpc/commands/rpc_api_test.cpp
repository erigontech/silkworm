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

#include "rpc_api.hpp"

#include <bit>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <utility>
#include <vector>

#include <boost/asio/thread_pool.hpp>
#include <catch2/catch.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/receipt.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/buffer.hpp>
#include <silkworm/node/db/genesis.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/ethdb/file/local_database.hpp>
#include <silkworm/rpc/http/request_handler.hpp>
#include <silkworm/rpc/test/api_test_database.hpp>
#include <silkworm/rpc/test/context_test_base.hpp>

namespace silkworm::rpc::commands {

// Function to recursively sort JSON arrays
void sort_array(nlohmann::json& jsonObj) {  // NOLINT(*-no-recursion)
    if (jsonObj.is_array()) {
        // Sort the elements within the array
        std::sort(jsonObj.begin(), jsonObj.end(), [](const nlohmann::json& a, const nlohmann::json& b) {
            return a.dump() < b.dump();
        });

        // Recursively sort nested arrays
        for (auto& item : jsonObj) {
            sort_array(item);
        }
    } else if (jsonObj.is_object()) {
        for (auto& item : jsonObj.items()) {
            sort_array(item.value());
        }
    }
}

// Function to compare two JSON objects while ignoring the order of elements in arrays
bool are_equivalent(const nlohmann::json& obj1, const nlohmann::json& obj2) {
    // Create copies of the JSON objects and sort their arrays
    nlohmann::json sortedObj1 = obj1;
    nlohmann::json sortedObj2 = obj2;
    sort_array(sortedObj1);
    sort_array(sortedObj2);

    // Serialize the sorted JSON objects to strings
    std::string str1 = sortedObj1.dump();
    std::string str2 = sortedObj2.dump();

    // Compare the sorted JSON strings
    return str1 == str2;
}

static const std::vector<std::string> tests_to_ignore = {
    "eth_estimateGas",         // call to oracle fails, needs fixing
    "debug_getRawReceipts",    // not implemented
    "eth_getProof",            // not implemented
    "eth_feeHistory",          // history not stored, needs fixing
    "eth_sendRawTransaction",  // call to oracle fails, needs fixing or mocking
};

// Exclude tests from sanitizer builds due to ASAN/TSAN warnings inside gRPC library
#ifndef SILKWORM_SANITIZE
TEST_CASE("rpc_api io (all files)", "[rpc][rpc_api]") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    auto tests_dir = test::get_tests_dir();
    for (const auto& test_file : std::filesystem::recursive_directory_iterator(tests_dir)) {
        if (!test_file.is_directory() && test_file.path().extension() == ".io") {
            auto test_name = test_file.path().filename().string();
            auto group_name = test_file.path().parent_path().filename().string();

            if (std::find(tests_to_ignore.begin(), tests_to_ignore.end(), group_name) != tests_to_ignore.end()) {
                continue;
            }

            std::ifstream test_stream(test_file.path());

            if (!test_stream.is_open()) {
                FAIL("Failed to open the file: " + test_file.path().string());
            }

            SECTION("RPC IO test " + group_name + " | " + test_name) {  // NOLINT(*-inefficient-string-concatenation)
                auto context = test::TestDatabaseContext();
                test::RpcApiTestBase<test::RequestHandler_ForTest> test_base{context.db};

                std::string line_out;
                std::string line_in;

                while (std::getline(test_stream, line_out) && std::getline(test_stream, line_in)) {
                    if (!line_out.starts_with(">> ") || !line_in.starts_with("<< ")) {
                        FAIL("Invalid test file format");
                    }

                    auto request = nlohmann::json::parse(line_out.substr(3));
                    auto expected = nlohmann::json::parse(line_in.substr(3));

                    http::Reply reply;
                    test_base.run<&test::RequestHandler_ForTest::request_and_create_reply>(request, reply);
                    INFO("Request:           " << request.dump())
                    INFO("Actual response:   " << reply.content)
                    INFO("Expected response: " << expected.dump())

                    if (test_name.find("invalid") != std::string::npos) {
                        CHECK(nlohmann::json::parse(reply.content).contains("error"));
                    } else {
                        CHECK(are_equivalent(nlohmann::json::parse(reply.content), expected));
                    }
                }
            }
        }
    }
}

TEST_CASE("rpc_api io (individual)", "[rpc][rpc_api][ignore]") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    auto context = test::TestDatabaseContext();
    test::RpcApiTestBase<test::RequestHandler_ForTest> test_base{context.db};

    SECTION("sample test") {
        auto request = R"({"jsonrpc":"2.0","id":1,"method":"debug_getRawTransaction","params":["0x74e41d593675913d6d5521f46523f1bd396dff1891bdb35f59be47c7e5e0b34b"]})"_json;
        http::Reply reply;

        test_base.run<&test::RequestHandler_ForTest::request_and_create_reply>(request, reply);
        CHECK(nlohmann::json::parse(reply.content) == R"({"jsonrpc":"2.0","id":1,"result":"0xf8678084342770c182520894658bdf435d810c91414ec09147daa6db624063798203e880820a95a0af5fc351b9e457a31f37c84e5cd99dd3c5de60af3de33c6f4160177a2c786a60a0201da7a21046af55837330a2c52fc1543cd4d9ead00ddf178dd96935b607ff9b"})"_json);
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::commands
