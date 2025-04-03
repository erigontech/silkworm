// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <type_traits>

namespace silkworm::snapshots {

template <typename T>
    requires(std::is_enum_v<T> and requires(T e) {
        enable_bitmask_operator_or(e);
    })
constexpr auto operator|(const T lhs, const T rhs) {
    using underlying = std::underlying_type_t<T>;
    return static_cast<T>(static_cast<underlying>(lhs) | static_cast<underlying>(rhs));
}
template <typename T>
    requires(std::is_enum_v<T> and requires(T e) {
        enable_bitmask_operator_and(e);
    })
constexpr auto operator&(const T lhs, const T rhs) {
    using underlying = std::underlying_type_t<T>;
    return static_cast<T>(static_cast<underlying>(lhs) & static_cast<underlying>(rhs));
}
template <typename T>
    requires(std::is_enum_v<T> and requires(T e) {
        enable_bitmask_operator_not(e);
    })
constexpr auto operator~(const T t) {
    using underlying = std::underlying_type_t<T>;
    return static_cast<T>(~static_cast<underlying>(t));
}

}  // namespace silkworm::snapshots
