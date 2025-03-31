// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::sentry {

struct Message {
    uint8_t id{0};
    Bytes data;
};

}  // namespace silkworm::sentry
