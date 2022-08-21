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

#include "binary_search.hpp"

namespace silkworm {

std::size_t binary_find_if(std::size_t n, absl::FunctionRef<bool(std::size_t)> f) {
    std::size_t i{0};
    std::size_t j{n};
    while (j > i) {
        const std::size_t count{j - i};
        const std::size_t m{i + count / 2};
        if (f(m)) {
            j = m;
        } else {
            i = m + 1;
        }
    }
    return i;
}

}  // namespace silkworm
