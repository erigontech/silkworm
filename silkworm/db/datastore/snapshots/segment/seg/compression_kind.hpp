// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>

#include "../../common/util/bitmask_operators.hpp"

namespace silkworm::snapshots::seg {

enum class CompressionKind : uint8_t {
    kNone = 0b0,
    kKeys = 0b1,
    kValues = 0b10,
    kAll = 0b11,
};

consteval void enable_bitmask_operator_and(CompressionKind);
consteval void enable_bitmask_operator_or(CompressionKind);
consteval void enable_bitmask_operator_not(CompressionKind);

}  // namespace silkworm::snapshots::seg
