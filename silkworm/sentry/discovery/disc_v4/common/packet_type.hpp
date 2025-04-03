// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>

namespace silkworm::sentry::discovery::disc_v4 {

// NOLINTNEXTLINE(readability-enum-initial-value)
enum class PacketType : uint8_t {
    kPing = 1,
    kPong,
    kFindNode,
    kNeighbors,
    kEnrRequest,
    kEnrResponse,
    kMaxValue = kEnrResponse,
};

}  // namespace silkworm::sentry::discovery::disc_v4
