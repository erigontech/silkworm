// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>

namespace silkworm::sentry::rlpx {

enum class DisconnectReason : uint8_t {
    kDisconnectRequested = 0,
    kNetworkError = 1,
    kProtocolError = 2,
    kUselessPeer = 3,
    kTooManyPeers = 4,
    kClientQuitting = 8,
    kPingTimeout = 11,
};

}  // namespace silkworm::sentry::rlpx
