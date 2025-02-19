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
