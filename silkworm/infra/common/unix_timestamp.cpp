// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "unix_timestamp.hpp"

namespace silkworm {

uint64_t unix_timestamp_from_time_point(std::chrono::time_point<std::chrono::system_clock> time_point) {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(time_point.time_since_epoch()).count());
}

std::chrono::time_point<std::chrono::system_clock> time_point_from_unix_timestamp(uint64_t timestamp) {
    return std::chrono::time_point<std::chrono::system_clock>{std::chrono::seconds(timestamp)};
}

}  // namespace silkworm
