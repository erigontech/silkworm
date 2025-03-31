// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <utility>

namespace silkworm {

template <typename T1, typename T2>
struct PairGetFirst {
    constexpr const T1& operator()(const std::pair<T1, T2>& p) const noexcept {
        return p.first;
    }
};

template <typename T1, typename T2>
struct PairGetSecond {
    constexpr const T2& operator()(const std::pair<T1, T2>& p) const noexcept {
        return p.second;
    }
};

};  // namespace silkworm
