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

#include <absl/strings/match.h>
#include <catch2/catch.hpp>

#include <silkworm/rpc/test/api_test_database.hpp>

namespace silkworm::rpc::http {

//! Ensure JSON RPC spec has been loaded before creating JsonRpcValidator instance
static JsonRpcValidator create_validator_for_test() {
    JsonRpcValidator::load_specification();
    return {};
}

TEST_CASE("rpc::http::JsonRpcValidator loads spec in constructor", "[rpc][http][json_rpc_validator]") {
    REQUIRE_NOTHROW(JsonRpcValidator::load_specification());
    CHECK(JsonRpcValidator::openrpc_version() == "1.2.4");
}

TEST_CASE("rpc::http::JsonRpcValidator validates request fields", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBlockByNumber"},
        {"params", {"0x0", true}},
        {"id", 1},
    };

    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result);
}

TEST_CASE("rpc::http::JsonRpcValidator detects missing request field", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

    nlohmann::json request = {
        {"method", "eth_getBlockByNumber"},
        {"params", {"0x0", true}},
        {"id", 1},
    };
    JsonRpcValidationResult result = validator.validate(request);
    CHECK(!result);
    CHECK(result.error() == "Request not valid, required fields: jsonrpc,id,method,params");

    request = {
        {"jsonrpc", "2.0"},
        {"params", {"0x0", true}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result);
    CHECK(result.error() == "Request not valid, required fields: jsonrpc,id,method,params");

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBlockByNumber"},
        {"params", {"0x0", true}},
    };
    result = validator.validate(request);
    CHECK(!result);
    CHECK(result.error() == "Request not valid, required fields: jsonrpc,id,method,params");
}

TEST_CASE("rpc::http::JsonRpcValidator validates invalid request fields", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

    nlohmann::json request = {
        {"jsonrpc", 2},
        {"method", "eth_getBlockByNumber"},
        {"params", {"0x0", true}},
        {"id", 1},
    };

    JsonRpcValidationResult result = validator.validate(request);
    CHECK(!result);
    CHECK(result.error() == "Invalid field: jsonrpc");

    request = {
        {"jsonrpc", "2.0"},
        {"method", 1},
        {"params", {"0x0", true}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result);
    CHECK(result.error() == "Invalid field: method");

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBlockByNumber"},
        {"params", "params"},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result);
    CHECK(result.error() == "Invalid field: params");

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBlockByNumber"},
        {"params", {"0x0", true}},
        {"id", "1"},
    };
    result = validator.validate(request);
    CHECK(!result);
    CHECK(result.error() == "Invalid field: id");
}

TEST_CASE("rpc::http::JsonRpcValidator accepts missing params field", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "debug_getBadBlocks"},
        {"id", 1},
    };

    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result);
}

TEST_CASE("rpc::http::JsonRpcValidator detects unknown fields", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

    nlohmann::json request = {
        {"unknown", "2.0"},
        {"method", "eth_getBlockByNumber"},
        {"params", {"0x0", true}},
        {"id", 1},
    };

    JsonRpcValidationResult result = validator.validate(request);
    CHECK(!result);
}

TEST_CASE("rpc::http::JsonRpcValidator accepts missing optional parameter", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa00000000000000000000000000000000000000"}},
        {"id", 1},
    };

    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result);
}

TEST_CASE("rpc::http::JsonRpcValidator validates string parameter", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa0"}},
        {"id", 1},
    };
    JsonRpcValidationResult result = validator.validate(request);
    CHECK(!result);

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xga00000000000000000000000000000000000000"}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result);

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"1xaa00000000000000000000000000000000000000"}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result);

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"aa00000000000000000000000000000000000000"}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result);

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"account"}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result);

    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {123}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result);
}

TEST_CASE("rpc::http::JsonRpcValidator validates optional parameter if provided", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa00000000000000000000000000000000000000", "not-valid-param"}},
        {"id", 1},
    };
    JsonRpcValidationResult result = validator.validate(request);
    CHECK(!result);
}

TEST_CASE("rpc::http::JsonRpcValidator validates enum", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa00000000000000000000000000000000000000", "earliest"}},
        {"id", 1},
    };
    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result);
    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa00000000000000000000000000000000000000", "latest"}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(result);

    CHECK(result);
    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa00000000000000000000000000000000000000", "other"}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result);
}

TEST_CASE("rpc::http::JsonRpcValidator validates hash", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa00000000000000000000000000000000000000", "0x76734e0205d8c4b711990ab957e86d3dc56d129600e60750552c95448a449794"}},
        {"id", 1},
    };
    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result);
    request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBalance"},
        {"params", {"0xaa00000000000000000000000000000000000000", "0x06734e0205d8c4b711990ab957e86d3dc56d129600e60750552c95448a44979"}},
        {"id", 1},
    };
    result = validator.validate(request);
    CHECK(!result);
}

TEST_CASE("rpc::http::JsonRpcValidator validates array", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "eth_getProof"},
        {"params", {"0xaa00000000000000000000000000000000000000", {"0x01", "0x02"}, "0x3"}}};
    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result);

    request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "eth_getProof"},
        {"params", {"0xaa00000000000000000000000000000000000000", {"0x01", "invalid"}, "0x3"}}};
    result = validator.validate(request);
    CHECK(!result);
}

TEST_CASE("rpc::http::JsonRpcValidator validates object", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

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
    CHECK(result);

    request = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "engine_exchangeTransitionConfigurationV1"},
        {"params", {{
                       {"terminalTotalDifficulty", "0x1"},
                       {"terminalBlockNumber", "0x1"},
                   }}}};
    result = validator.validate(request);
    CHECK(!result);

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
    CHECK(!result);

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
    CHECK(!result);

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
    CHECK(!result);
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
    CHECK(!result);
}

TEST_CASE("rpc::http::JsonRpcValidator validates uppercase hex value", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBlockByNumber"},
        {"params", {"0xF42405", true}},
        {"id", 1},
    };

    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result);
}

TEST_CASE("rpc::http::JsonRpcValidator validates `data` field", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBlockByNumber"},
        {"params", {"0xF42405", true}},
        {"id", 1},
    };

    JsonRpcValidationResult result = validator.validate(request);
    CHECK(result);
}

TEST_CASE("rpc::http::JsonRpcValidator validates nested arrays", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

    auto request1 = R"({
            "jsonrpc":"2.0",
            "method":"eth_getLogs",
            "params":[
                {
                    "fromBlock": "0x10B10B2",
                    "toBlock": "0x10B10B3",
                    "address": ["0x00000000219ab540356cbb839cbe05303d7705fa"],
                    "topics": null
                }
            ],
            "id":3
    })"_json;
    JsonRpcValidationResult result1 = validator.validate(request1);
    CHECK(result1);

    auto request2 = R"({
            "jsonrpc":"2.0",
            "method":"eth_getLogs",
            "params":[
                {
                    "fromBlock": "0x10B10B2",
                    "toBlock": "0x10B10B3",
                    "address": ["0x00000000219ab540356cbb839cbe05303d7705fa"],
                    "topics": "0x76734e0205d8c4b711990ab957e86d3dc56d129600e60750552c95448a449794"
                }
            ],
            "id":3
    })"_json;
    JsonRpcValidationResult result2 = validator.validate(request2);
    CHECK(result2);

    auto request3 = R"({
            "jsonrpc":"2.0",
            "method":"eth_getLogs",
            "params":[
                {
                    "fromBlock": "0x10B10B2",
                    "toBlock": "0x10B10B3",
                    "address": ["0x00000000219ab540356cbb839cbe05303d7705fa"],
                    "topics": [
                        "0x76734e0205d8c4b711990ab957e86d3dc56d129600e60750552c95448a449794",
                        "0x76734e0205d8c4b711990ab957e86d3dc56d129600e60750552c95448a449795"
                        ]
                }
            ],
            "id":3
    })"_json;
    JsonRpcValidationResult result3 = validator.validate(request3);
    CHECK(result3);
}

TEST_CASE("rpc::http::JsonRpcValidator validates spec test request", "[rpc][http][json_rpc_validator]") {
    JsonRpcValidator validator{create_validator_for_test()};

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
                    const auto result = validator.validate(request);
                    if (!absl::StrContains(test_name, "invalid")) {
                        CHECK(result);
                    }
                }
            }
        }
    }
}

}  // namespace silkworm::rpc::http
