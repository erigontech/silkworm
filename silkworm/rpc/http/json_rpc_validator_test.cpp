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

#include "json_rpc_validator.hpp"

#include <catch2/catch.hpp>

#include <silkworm/rpc/test/api_test_database.hpp>

namespace silkworm::rpc::http {

TEST_CASE("rpc::http::JsonRpcValidator loads spec in constructor", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{};
    CHECK(validator.openrpc_version() == "1.2.4");
}

TEST_CASE("rpc::http::JsonRpcValidator validates request fields", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBlockByNumber"},
        {"params", {"0x0", true}},
        {"id", 1},
    };

    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result.is_valid);
}

TEST_CASE("rpc::http::JsonRpcValidator detects missing request field", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{};

    nlohmann::json request = {
        {"method", "eth_getBlockByNumber"},
        {"params", {"0x0", true}},
        {"id", 1},
    };
    JsonRpcValidationResult result = validator.validate(request);
    CHECK(!result.is_valid);
    CHECK(result.error_message == "Request not valid, required fields: jsonrpc,id,method,params");

    request = {
        {"jsonrpc", "2.0"},
        {"params", {"0x0", true}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result.is_valid);
    CHECK(result.error_message == "Request not valid, required fields: jsonrpc,id,method,params");

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBlockByNumber"},
        {"params", {"0x0", true}},
    };
    result = validator.validate(request);
    CHECK(!result.is_valid);
    CHECK(result.error_message == "Request not valid, required fields: jsonrpc,id,method,params");
}

TEST_CASE("rpc::http::JsonRpcValidator validates invalid request fields", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{};

    nlohmann::json request = {
        {"jsonrpc", 2},
        {"method", "eth_getBlockByNumber"},
        {"params", {"0x0", true}},
        {"id", 1},
    };

    JsonRpcValidationResult result = validator.validate(request);
    CHECK(!result.is_valid);
    CHECK(result.error_message == "Invalid field: jsonrpc");

    request = {
        {"jsonrpc", "2.0"},
        {"method", 1},
        {"params", {"0x0", true}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result.is_valid);
    CHECK(result.error_message == "Invalid field: method");

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBlockByNumber"},
        {"params", "params"},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result.is_valid);
    CHECK(result.error_message == "Invalid field: params");

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBlockByNumber"},
        {"params", {"0x0", true}},
        {"id", "1"},
    };
    result = validator.validate(request);
    CHECK(!result.is_valid);
    CHECK(result.error_message == "Invalid field: id");
}


TEST_CASE("rpc::http::JsonRpcValidator accepts missing params field", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "debug_getBadBlocks"},
        {"id", 1},
    };

    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result.is_valid);
}

TEST_CASE("rpc::http::JsonRpcValidator detects unknown fields", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{};

    nlohmann::json request = {
        {"unknown", "2.0"},
        {"method", "eth_getBlockByNumber"},
        {"params", {"0x0", true}},
        {"id", 1},
    };

    JsonRpcValidationResult result = validator.validate(request);
    CHECK(!result.is_valid);
}

TEST_CASE("rpc::http::JsonRpcValidator accepts missing optional parameter", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa00000000000000000000000000000000000000"}},
        {"id", 1},
    };

    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result.is_valid);
}

TEST_CASE("rpc::http::JsonRpcValidator validates string parameter", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa0"}},
        {"id", 1},
    };
    JsonRpcValidationResult result = validator.validate(request);
    CHECK(!result.is_valid);

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xga00000000000000000000000000000000000000"}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result.is_valid);

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"1xaa00000000000000000000000000000000000000"}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result.is_valid);

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"aa00000000000000000000000000000000000000"}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result.is_valid);

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"account"}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result.is_valid);

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {123}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result.is_valid);
}

TEST_CASE("rpc::http::JsonRpcValidator validates optional parameter if provided", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa00000000000000000000000000000000000000", "not-valid-param"}},
        {"id", 1},
    };
    JsonRpcValidationResult result = validator.validate(request);
    CHECK(!result.is_valid);
}

TEST_CASE("rpc::http::JsonRpcValidator validates enum", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa00000000000000000000000000000000000000", "earliest"}},
        {"id", 1},
    };
    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result.is_valid);
    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa00000000000000000000000000000000000000", "latest"}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(result.is_valid);

    CHECK(result.is_valid);
    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa00000000000000000000000000000000000000", "other"}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result.is_valid);
}

TEST_CASE("rpc::http::JsonRpcValidator validates hash", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa00000000000000000000000000000000000000", "0x76734e0205d8c4b711990ab957e86d3dc56d129600e60750552c95448a449794"}},
        {"id", 1},
    };
    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result.is_valid);
    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa00000000000000000000000000000000000000", "0x06734e0205d8c4b711990ab957e86d3dc56d129600e60750552c95448a44979"}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result.is_valid);
}

TEST_CASE("rpc::http::JsonRpcValidator validates array", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "eth_getProof"},
        {"params", {"0xaa00000000000000000000000000000000000000", {"0x01", "0x02"}, "0x3"}}};
    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result.is_valid);

    request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "eth_getProof"},
        {"params", {"0xaa00000000000000000000000000000000000000", {"0x01", "invalid"}, "0x3"}}};
    result = validator.validate(request);
    CHECK(!result.is_valid);
}

TEST_CASE("rpc::http::JsonRpcValidator validates object", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "engine_exchangeTransitionConfigurationV1"},
        {"params", {{
                       {"terminalTotalDifficulty", "0x1"},
                       {"terminalBlockHash", "0x76734e0205d8c4b711990ab957e86d3dc56d129600e60750552c95448a449794"},
                       {"terminalBlockNumber", "0x1"},
                   }}}};
    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result.is_valid);

    request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "engine_exchangeTransitionConfigurationV1"},
        {"params", {{
                       {"terminalTotalDifficulty", "0x1"},
                       {"terminalBlockNumber", "0x1"},
                   }}}};
    result = validator.validate(request);
    CHECK(!result.is_valid);

    request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "engine_exchangeTransitionConfigurationV1"},
        {"params", {{
                       {"terminalTotalDifficulty", "1x1"},
                       {"terminalBlockHash", "0x76734e0205d8c4b711990ab957e86d3dc56d129600e60750552c95448a449794"},
                       {"terminalBlockNumber", "0x1"},
                   }}}};
    result = validator.validate(request);
    CHECK(!result.is_valid);

    request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "engine_exchangeTransitionConfigurationV1"},
        {"params", {{
                       {"terminalTotalDifficulty", "0x1"},
                       {"terminalBlockHash", "1x76734e0205d8c4b711990ab957e86d3dc56d129600e60750552c95448a449794"},
                       {"terminalBlockNumber", "0x1"},
                   }}}};
    result = validator.validate(request);
    CHECK(!result.is_valid);

    request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "engine_exchangeTransitionConfigurationV1"},
        {"params", {{
                       {"terminalTotalDifficulty", "0x1"},
                       {"terminalBlockHash", "0x76734e0205d8c4b711990ab957e86d3dc56d129600e60750552c95448a449794"},
                       {"terminalBlockNumber", "1x1"},
                   }}}};
    result = validator.validate(request);
    CHECK(!result.is_valid);
    request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "engine_exchangeTransitionConfigurationV1"},
        {"params", {{
                       {"terminalTotalDifficulty", "0x1"},
                       {"terminalBlockHash", "0x76734e0205d8c4b711990ab957e86d3dc56d129600e60750552c95448a449794"},
                       {"terminalBlockNumber", "0x1"},
                       {"extra", "extra"},
                   }}}};
    result = validator.validate(request);
    CHECK(!result.is_valid);
}

TEST_CASE("rpc::http::JsonRpcValidator validates spec test request", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator;

    const auto tests_dir = test::get_tests_dir();
    for (const auto& test_file : std::filesystem::recursive_directory_iterator(tests_dir)) {
        if (!test_file.is_directory() && test_file.path().extension() == ".io") {
            auto test_name = test_file.path().filename().string();
            auto group_name = test_file.path().parent_path().filename().string();
            SECTION("RPC IO test " + group_name + " | " + test_name) {  // NOLINT(*-inefficient-string-concatenation)
                std::ifstream test_stream(test_file.path());
                std::string request_line;
                if (std::getline(test_stream, request_line) && request_line.starts_with(">> ")) {
                    auto request = nlohmann::json::parse(request_line.substr(3));
                    const auto results = validator.validate(request);
                    if (test_name.find("invalid") == std::string::npos) {
                        CHECK(results.is_valid);
                    }
                }
            }
        }
    }
}

}  // namespace silkworm::rpc::http
