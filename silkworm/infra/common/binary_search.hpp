/*
   Copyright 2022 The Silkworm Authors

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

#include <cstddef>

#include <absl/functional/function_ref.h>

namespace silkworm {

// binary_find_if uses binary search to find and return the smallest index i
// in [0, n) at which f(i) is true, assuming that on the range [0, n),
// f(i) == true implies f(i+1) == true. That is, binary_find_if requires that
// f is false for some (possibly empty) prefix of the input range [0, n)
// and then true for the (possibly empty) remainder; binary_find_if returns
// the first true index. If there is no such index, binary_find_if returns n.
// binary_find_if calls f(i) only for i in the range [0, n).
//
// For a sorted vector<int> vec and some int value, the following should return the same index:
//
// std::upper_bound(vec.begin(), vec.end(), value) - vec.begin();
// std::find_if(vec.begin(), vec.end(), [&](int x) { return x > value;}) - vec.begin();
// binary_find_if(vec.size(), [&](size_t i) { return vec[i] > value;});
//
// N.B. Also similar to golang sort.Search.
size_t binary_find_if(size_t n, absl::FunctionRef<bool(size_t)> f);

}  // namespace silkworm
