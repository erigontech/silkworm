/*
   Copyright 2022 The Silkworm Authors

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

#include <iostream>

#include <benchmark/benchmark.h>
#include <nlohmann/json.hpp>

#include "json_rpc_validator.hpp"

static silkworm::rpc::http::JsonRpcValidator validator{};

// static nlohmann::json request = {
//     {"jsonrpc", "2.0"},
//     {"id", 1},
//     {"method", "engine_exchangeTransitionConfigurationV1"},
//     {"params", {{
//                    {"terminalTotalDifficulty", "0x1"},
//                    {"terminalBlockHash", "0x76734e0205d8c4b711990ab957e86d3dc56d129600e60750552c95448a449794"},
//                    {"terminalBlockNumber", "0x1"},
//                }}}};

static nlohmann::json request = {
    {"jsonrpc", "2.0"},
    {"method", "eth_getBlockByNumber"},
    {"params", {"0x0", true}},
    {"id", 1},
};

static void json_rpc_validator(benchmark::State& state) {
    for ([[maybe_unused]] auto _ : state) {
        validator.validate(request);
    }
}

BENCHMARK(json_rpc_validator);
