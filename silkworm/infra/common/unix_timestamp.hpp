// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <cstdint>

namespace silkworm {

uint64_t unix_timestamp_from_time_point(std::chrono::time_point<std::chrono::system_clock> time_point);
std::chrono::time_point<std::chrono::system_clock> time_point_from_unix_timestamp(uint64_t timestamp);

}  // namespace silkworm
