// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ping_message.hpp"

#include <silkworm/core/rlp/encode_vector.hpp>

namespace silkworm::sentry::rlpx {

const uint8_t PingMessage::kId = 2;
const uint8_t PongMessage::kId = 3;

Bytes PingMessage::rlp_encode() const {
    Bytes data;
    rlp::encode(data, std::vector<uint8_t>{});
    return data;
}

Bytes PongMessage::rlp_encode() const {
    Bytes data;
    rlp::encode(data, std::vector<uint8_t>{});
    return data;
}

sentry::Message PingMessage::to_message() const {
    return sentry::Message{kId, rlp_encode()};
}

sentry::Message PongMessage::to_message() const {
    return sentry::Message{kId, rlp_encode()};
}

}  // namespace silkworm::sentry::rlpx
