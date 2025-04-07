// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "disconnect_message.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/rlp/encode_vector.hpp>

namespace silkworm::sentry::rlpx {

static Bytes rlp_encode(const auto value) {
    Bytes data;
    rlp::encode(data, value);
    return data;
}

TEST_CASE("DisconnectMessage.rlp_decode") {
    CHECK(DisconnectMessage::rlp_decode(rlp_encode(std::vector<uint8_t>{4})).reason == DisconnectReason::kTooManyPeers);
    CHECK(DisconnectMessage::rlp_decode(rlp_encode(uint8_t(4))).reason == DisconnectReason::kTooManyPeers);
    CHECK(DisconnectMessage::rlp_decode(rlp_encode(std::vector<uint8_t>{})).reason == DisconnectReason::kDisconnectRequested);
    CHECK(DisconnectMessage::rlp_decode(Bytes{}).reason == DisconnectReason::kDisconnectRequested);
}

}  // namespace silkworm::sentry::rlpx
