// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <cstdint>

namespace silkworm::clock_time {

uint64_t now();
uint64_t since(uint64_t start);

}  // namespace silkworm::clock_time
