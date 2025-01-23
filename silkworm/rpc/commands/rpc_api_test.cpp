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
#include <vector>

#include <nlohmann/json.hpp>

#include <silkworm/rpc/test_util/api_test_database.hpp>

namespace silkworm::rpc::commands {

#ifdef notdef  // temporarily commented out waiting for LocalTransaction implementation
using test_util::RequestHandlerForTest;
using test_util::RpcApiTestBase;
#endif

// Function to recursively sort JSON arrays
void sort_array(nlohmann::json& json_obj) {  // NOLINT(*-no-recursion)
    if (json_obj.is_array()) {
        // Sort the elements within the array
        std::sort(json_obj.begin(), json_obj.end(), [](const nlohmann::json& a, const nlohmann::json& b) {
            return a.dump() < b.dump();
        });

        // Recursively sort nested arrays
        for (auto& item : json_obj) {
            sort_array(item);
        }
    } else if (json_obj.is_object()) {
        for (auto& item : json_obj.items()) {
            sort_array(item.value());
        }
    }
}

// Function to compare two JSON objects while ignoring the order of elements in arrays
bool are_equivalent(const nlohmann::json& obj1, const nlohmann::json& obj2) {
    // Create copies of the JSON objects and sort their arrays
    nlohmann::json sorted_obj1 = obj1;
    nlohmann::json sorted_obj2 = obj2;
    sort_array(sorted_obj1);
    sort_array(sorted_obj2);

    // Serialize the sorted JSON objects to strings
    std::string str1 = sorted_obj1.dump();
    std::string str2 = sorted_obj2.dump();

    // Compare the sorted JSON strings
    return str1 == str2;
}

static const std::vector<std::string> kTestsToIgnore = {
    "eth_getProof",            // not implemented
    "debug_getRawReceipts",    // not implemented
    "eth_sendRawTransaction",  // call to txpool fails, needs mocking
};

static const std::vector<std::string> kSubtestsToIgnore = {
    "create-al-multiple-reads.io",  // eth_createAccessList: expected value doesn't contain gas optimization
    "estimate-simple-transfer.io",  // eth_estimateGas: without gas paramters doesn't support base_fee_gas of block as default gas
    "estimate-simple-contract.io",  // eth_estimateGas: without gas paramters doesn't support base_fee_gas of block as default gas
    "call-simple-transfer.io",      // eth_call: without gas paramters doesn't support base_fee_gas of block as default gas
    "call-simple-contract.io",      // eth_call: without gas paramters doesn't support base_fee_gas of block as default gas
};

#ifdef notdef  // temporarily commented out waiting for LocalTransaction implementation
// Exclude tests from sanitizer builds due to ASAN/TSAN warnings inside gRPC library
#ifndef SILKWORM_SANITIZE
TEST_CASE("rpc_api io (all files)", "[rpc][rpc_api]") {
    auto tests_dir = db::test_util::get_tests_dir();
    for (const auto& test_file : std::filesystem::recursive_directory_iterator(tests_dir)) {
        if (!test_file.is_directory() && test_file.path().extension() == ".io") {
            auto test_name = test_file.path().filename().string();
            auto group_name = test_file.path().parent_path().filename().string();

            if (std::find(kTestsToIgnore.begin(), kTestsToIgnore.end(), group_name) != kTestsToIgnore.end()) {
                continue;
            }

            if (std::find(kSubtestsToIgnore.begin(), kSubtestsToIgnore.end(), test_name) != kSubtestsToIgnore.end()) {
                continue;
            }

            std::ifstream test_stream(test_file.path());

            if (!test_stream.is_open()) {
                FAIL("Failed to open the file: " + test_file.path().string());
            }

            SECTION("RPC IO test " + group_name + " | " + test_name) {  // NOLINT(*-inefficient-string-concatenation)
                TemporaryDirectory tmp_dir;
                auto context = db::test_util::TestDatabaseContext(tmp_dir);
                RpcApiTestBase<RequestHandlerForTest> test_base{context.mdbx_env()};

                std::string line_out;
                std::string line_in;

                while (std::getline(test_stream, line_out) && std::getline(test_stream, line_in)) {
                    if (!line_out.starts_with(">> ") || !line_in.starts_with("<< ")) {
                        FAIL("Invalid test file format");
                    }

                    auto request = nlohmann::json::parse(line_out.substr(3));
                    auto expected = nlohmann::json::parse(line_in.substr(3));

                    std::string response;
                    test_base.run<&RequestHandlerForTest::request_and_create_reply>(request, response);
                    INFO("Request:           " << request.dump());
                    INFO("Actual response:   " << response);
                    INFO("Expected response: " << expected.dump());

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

#ifdef SILKWORM_TEST_SKIP
TEST_CASE("rpc_api io (individual)", "[rpc][rpc_api]") {
    TemporaryDirectory tmp_dir;
    auto context = db::test_util::TestDatabaseContext(tmp_dir);
    RpcApiTestBase<RequestHandlerForTest> test_base{context.mdbx_env()};

    SECTION("sample test") {
        auto request = R"({"jsonrpc":"2.0","id":1,"method":"debug_getRawTransaction","params":["0x74e41d593675913d6d5521f46523f1bd396dff1891bdb35f59be47c7e5e0b34b"]})"_json;
        std::string response;

        test_base.run<&RequestHandlerForTest::request_and_create_reply>(request, response);
        CHECK(nlohmann::json::parse(response) == R"({"jsonrpc":"2.0","id":1,"result":"0xf8678084342770c182520894658bdf435d810c91414ec09147daa6db624063798203e880820a95a0af5fc351b9e457a31f37c84e5cd99dd3c5de60af3de33c6f4160177a2c786a60a0201da7a21046af55837330a2c52fc1543cd4d9ead00ddf178dd96935b607ff9b"})"_json);
    }
}
#endif  // SILKWORM_TEST_SKIP

#endif  // SILKWORM_SANITIZE

#endif

}  // namespace silkworm::rpc::commands
