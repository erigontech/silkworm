// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "clock_time.hpp"

namespace silkworm::clock_time {

uint64_t now() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

uint64_t since(uint64_t start) {
    return now() - start;
}

}  // namespace silkworm::clock_time
