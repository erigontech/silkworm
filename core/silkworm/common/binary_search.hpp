/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_COMMON_BINARY_SEARCH_HPP_
#define SILKWORM_COMMON_BINARY_SEARCH_HPP_

namespace silkworm {

// upper_bound uses binary search to find and return the smallest index i
// in [0, n) at which f(i) is true, assuming that on the range [0, n),
// f(i) == true implies f(i+1) == true. That is, upper_bound requires that
// f is false for some (possibly empty) prefix of the input range [0, n)
// and then true for the (possibly empty) remainder; upper_bound returns
// the first true index. If there is no such index, upper_bound returns n.
// upper_bound calls f(i) only for i in the range [0, n).
//
// For a vector<int> v and some int value, the following two are equivalent:
//
// std::upper_bound(v.begin(), v.end(), value) - v.begin();
//
// silkworm::upper_bound(v.size(), [&](size_t i) { return v[i] > value;});
//
// N.B. Also similar to golang sort.Search.
template <class SizeType, class UnaryPredicate>
SizeType upper_bound(SizeType n, UnaryPredicate f) {
    SizeType i{0};
    SizeType j{n};
    while (const auto count{j - i}) {
        const auto m{i + count / 2};
        if (f(m)) {
            j = m;
        } else {
            i = m + 1;
        }
    }
    return i;
}

}  // namespace silkworm

#endif  // SILKWORM_COMMON_BINARY_SEARCH_HPP_
