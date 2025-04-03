// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "fork_choice.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

namespace silkworm::rpc {

using namespace evmc::literals;

TEST_CASE("serialize ForkChoiceStateV1", "[silkworm::json][to_json]") {
    ForkChoiceState forkchoice_state{
        .head_block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
        .safe_block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
        .finalized_block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32};

    nlohmann::json j = forkchoice_state;
    CHECK(j == R"({
        "headBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
        "safeBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
        "finalizedBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858"
    })"_json);
}

TEST_CASE("deserialize ForkChoiceStateV1", "[silkworm::json][from_json]") {
    nlohmann::json j = R"({
        "headBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
        "safeBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
        "finalizedBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858"
    })"_json;

    ForkChoiceState forkchoice_state = j;
    CHECK(forkchoice_state.head_block_hash == 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32);
    CHECK(forkchoice_state.safe_block_hash == 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32);
    CHECK(forkchoice_state.finalized_block_hash == 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32);
}

TEST_CASE("serialize ForkChoiceUpdatedReply", "[silkworm::json][to_json]") {
    ForkChoiceUpdatedReply fcu_reply{
        .payload_status = PayloadStatus::kAccepted,
        .payload_id = 0};

    nlohmann::json j = fcu_reply;
    CHECK(j == R"({
        "payloadStatus":{"status":"ACCEPTED"},
        "payloadId":"0x0000000000000000"
    })"_json);
}

}  // namespace silkworm::rpc
