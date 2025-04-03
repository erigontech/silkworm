// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <concepts>
#include <limits>

namespace silkworm::math {

// Computes the least integer value not less than num
template <std::integral T = int>
constexpr T int_ceil(double num) {
    if (num <= static_cast<double>(std::numeric_limits<T>::min())) {
        return std::numeric_limits<T>::min();
    }
    if (num >= static_cast<double>(std::numeric_limits<T>::max())) {
        return std::numeric_limits<T>::max();
    }

    const T i{static_cast<T>(num)};
    return num > static_cast<double>(i) ? i + 1 : i;
}

}  // namespace silkworm::math
