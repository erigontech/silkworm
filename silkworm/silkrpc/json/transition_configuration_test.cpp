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

#include "transition_configuration.hpp"

#include <catch2/catch.hpp>
#include <evmc/evmc.hpp>

namespace silkworm::rpc {

using Catch::Matchers::Message;
using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

TEST_CASE("serialize TransitionConfigurationV1", "[silkworm::json][to_json]") {
    TransitionConfiguration transition_configuration{
        .terminal_total_difficulty = 0xf4240,
        .terminal_block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
        .terminal_block_number = 0x0};

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
        .terminal_block_number = 0x0};
    CHECK(actual_transition_configuration.terminal_total_difficulty == expected_transition_configuration.terminal_total_difficulty);
    CHECK(actual_transition_configuration.terminal_block_hash == expected_transition_configuration.terminal_block_hash);
    CHECK(actual_transition_configuration.terminal_block_number == expected_transition_configuration.terminal_block_number);
}

}  // namespace silkworm::rpc
