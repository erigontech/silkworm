// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include <benchmark/benchmark.h>
#include <nlohmann/json.hpp>

#include "validator.hpp"

static silkworm::rpc::json_rpc::Validator validator{};

static const nlohmann::json kRequests[2] = {
    {
        {"jsonrpc", "2.0"},
        {"method", "eth_getBlockByNumber"},
        {"params", {"0x0", true}},
        {"id", 1},
    },
    {{"jsonrpc", "2.0"},
     {"id", 1},
     {"method", "engine_exchangeTransitionConfigurationV1"},
     {"params", {{
                    {"terminalTotalDifficulty", "0x1"},
                    {"terminalBlockHash", "0x76734e0205d8c4b711990ab957e86d3dc56d129600e60750552c95448a449794"},
                    {"terminalBlockNumber", "0x1"},
                }}}}};

static void json_rpc_validator(benchmark::State& state) {
    nlohmann::json json = kRequests[state.range(0)];
    for ([[maybe_unused]] auto _ : state) {
        validator.validate(json);
    }
}

BENCHMARK(json_rpc_validator)->Arg(0)->Arg(1);
