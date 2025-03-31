// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "payload_attributes.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

namespace silkworm::rpc {

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

TEST_CASE("serialize PayloadAttributesV1", "[silkworm::json][to_json]") {
    PayloadAttributes payload_attributes{
        .timestamp = 0x1,
        .prev_randao = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
        .suggested_fee_recipient = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address};

    nlohmann::json j = payload_attributes;
    CHECK(j == R"({
        "timestamp":"0x1",
        "prevRandao":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
        "suggestedFeeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
    })"_json);
}

TEST_CASE("deserialize PayloadAttributesV1", "[silkworm::json][from_json]") {
    nlohmann::json j = R"({
        "timestamp":"0x1",
        "prevRandao":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
        "suggestedFeeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
    })"_json;

    PayloadAttributes payload_attributes = j;
    CHECK(payload_attributes.timestamp == 0x1);
    CHECK(payload_attributes.prev_randao == 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32);
    CHECK(payload_attributes.suggested_fee_recipient == 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address);
}

}  // namespace silkworm::rpc
