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

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include <absl/strings/match.h>
#include <catch2/catch.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/db/test_util/test_database_context.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/test_util/api_test_database.hpp>

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
    "eth_getProof",            // not implemented
    "debug_getRawReceipts",    // not implemented
    "eth_sendRawTransaction",  // call to txpool fails, needs mocking
};

static const std::vector<std::string> subtests_to_ignore = {
    "create-al-multiple-reads.io",  // eth_createAccessList: expected value doesn't contain gas optimization
    "estimate-simple-transfer.io",  // eth_estimateGas doesn't expect baseFeeGas without GasPrice
    "estimate-simple-contract.io",  // eth_estimateGas doesn't expect baseFeeGas without GasPrice
};

// Exclude tests from sanitizer builds due to ASAN/TSAN warnings inside gRPC library
#ifndef SILKWORM_SANITIZE
TEST_CASE("rpc_api io (all files)", "[rpc][rpc_api]") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    auto tests_dir = db::test_util::get_tests_dir();
    for (const auto& test_file : std::filesystem::recursive_directory_iterator(tests_dir)) {
        if (!test_file.is_directory() && test_file.path().extension() == ".io") {
            auto test_name = test_file.path().filename().string();
            auto group_name = test_file.path().parent_path().filename().string();

            if (std::find(tests_to_ignore.begin(), tests_to_ignore.end(), group_name) != tests_to_ignore.end()) {
                continue;
            }

            if (std::find(subtests_to_ignore.begin(), subtests_to_ignore.end(), test_name) != subtests_to_ignore.end()) {
                continue;
            }

            std::ifstream test_stream(test_file.path());

            if (!test_stream.is_open()) {
                FAIL("Failed to open the file: " + test_file.path().string());
            }

            SECTION("RPC IO test " + group_name + " | " + test_name) {  // NOLINT(*-inefficient-string-concatenation)
                auto context = db::test_util::TestDatabaseContext();
                test::RpcApiTestBase<test::RequestHandler_ForTest> test_base{context.db};

                std::string line_out;
                std::string line_in;

                while (std::getline(test_stream, line_out) && std::getline(test_stream, line_in)) {
                    if (!line_out.starts_with(">> ") || !line_in.starts_with("<< ")) {
                        FAIL("Invalid test file format");
                    }

                    auto request = nlohmann::json::parse(line_out.substr(3));
                    auto expected = nlohmann::json::parse(line_in.substr(3));

                    std::string response;
                    test_base.run<&test::RequestHandler_ForTest::request_and_create_reply>(request, response);
                    INFO("Request:           " << request.dump())
                    INFO("Actual response:   " << response)
                    INFO("Expected response: " << expected.dump())

                    if (absl::StrContains(test_name, "invalid")) {
                        CHECK(nlohmann::json::parse(response).contains("error"));
                    } else {
                        CHECK(are_equivalent(nlohmann::json::parse(response), expected));
                    }
                }
            }
        }
    }
}

TEST_CASE("rpc_api io (individual)", "[rpc][rpc_api][ignore]") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    auto context = db::test_util::TestDatabaseContext();
    test::RpcApiTestBase<test::RequestHandler_ForTest> test_base{context.db};

    SECTION("sample test") {
        auto request = R"({"jsonrpc":"2.0","id":1,"method":"debug_getRawTransaction","params":["0x74e41d593675913d6d5521f46523f1bd396dff1891bdb35f59be47c7e5e0b34b"]})"_json;
        std::string response;

        test_base.run<&test::RequestHandler_ForTest::request_and_create_reply>(request, response);
        CHECK(nlohmann::json::parse(response) == R"({"jsonrpc":"2.0","id":1,"result":"0xf8678084342770c182520894658bdf435d810c91414ec09147daa6db624063798203e880820a95a0af5fc351b9e457a31f37c84e5cd99dd3c5de60af3de33c6f4160177a2c786a60a0201da7a21046af55837330a2c52fc1543cd4d9ead00ddf178dd96935b607ff9b"})"_json);
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::commands
