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

#include "binary_find_if.hpp"

namespace silkworm {

size_t binary_find_if(size_t n, absl::FunctionRef<bool(size_t)> f) {
    size_t i{0};
    size_t j{n};
    while (j > i) {
        const size_t count{j - i};
        const size_t m{i + count / 2};
        if (f(m)) {
            j = m;
        } else {
            i = m + 1;
        }
    }
    return i;
}

}  // namespace silkworm
