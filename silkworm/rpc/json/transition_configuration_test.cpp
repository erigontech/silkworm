// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "transition_configuration.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

namespace silkworm::rpc {

using evmc::literals::operator""_bytes32;

TEST_CASE("serialize TransitionConfigurationV1", "[silkworm::json][to_json]") {
    TransitionConfiguration transition_configuration{
        .terminal_total_difficulty = 0xf4240,
        .terminal_block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
        .terminal_block_num = 0x0};

    nlohmann::json j = transition_configuration;
    CHECK(j["terminalTotalDifficulty"] == "0xf4240");
    CHECK(j["terminalBlockHash"] == "0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858");
    CHECK(j["terminalBlockNumber"] == "0x0");
}

TEST_CASE("deserialize TransitionConfigurationV1", "[silkworm::json][from_json]") {
    TransitionConfiguration actual_transition_configuration = R"({
        "terminalTotalDifficulty":"0xf4240",
        "terminalBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
        "terminalBlockNumber":"0x0"
    })"_json;

    TransitionConfiguration expected_transition_configuration{
        .terminal_total_difficulty = 0xf4240,
        .terminal_block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
        .terminal_block_num = 0x0};
    CHECK(actual_transition_configuration.terminal_total_difficulty == expected_transition_configuration.terminal_total_difficulty);
    CHECK(actual_transition_configuration.terminal_block_hash == expected_transition_configuration.terminal_block_hash);
    CHECK(actual_transition_configuration.terminal_block_num == expected_transition_configuration.terminal_block_num);
}

}  // namespace silkworm::rpc
