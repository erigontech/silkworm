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

#include <algorithm>
#include <iterator>
#include <vector>

namespace silkworm {

template <std::input_iterator It>
void iterator_read_into(It it, size_t count, std::vector<typename It::value_type>& out) {
    std::copy_n(std::make_move_iterator(std::move(it)), count, std::back_inserter(out));
}

template <std::input_iterator It>
std::vector<typename It::value_type> iterator_read_into_vector(It it, size_t count) {
    std::vector<typename It::value_type> out;
    out.reserve(count);
    iterator_read_into(std::move(it), count, out);
    return out;
}

}  // namespace silkworm
