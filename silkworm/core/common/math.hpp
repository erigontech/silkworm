/*
   Copyright 2023 The Silkworm Authors

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

#include <concepts>
#include <limits>

#include <silkworm/core/common/assert.hpp>

namespace silkworm::math {

// Computes the least integer value not less than num
template <std::integral T = int>
constexpr T int_ceil(double num) {
    SILKWORM_ASSERT(num >= static_cast<double>(std::numeric_limits<T>::min()));
    SILKWORM_ASSERT(num <= static_cast<double>(std::numeric_limits<T>::max()));

    const T i{static_cast<T>(num)};
    return num > static_cast<double>(i) ? i + 1 : i;
}

}  // namespace silkworm::math
