/*
   Copyright 2024 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

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
