// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <compare>

namespace silkworm::views {

struct MergeCompareFunc {
    template <typename T>
    constexpr std::strong_ordering operator()(const T& lhs, const T& rhs) const noexcept {
        return std::compare_strong_order_fallback(lhs, rhs);
    }
};

}  // namespace silkworm::views
