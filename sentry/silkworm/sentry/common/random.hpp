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

#include <iterator>
#include <list>
#include <optional>
#include <random>

#include <silkworm/common/base.hpp>

namespace silkworm::sentry::common {

Bytes random_bytes(Bytes::size_type size);

template <typename T>
std::optional<typename std::list<T>::iterator> random_list_item(std::list<T>& l) {
    if (l.empty())
        return std::nullopt;

    std::default_random_engine random_engine{std::random_device{}()};
    std::uniform_int_distribution<size_t> random_distribution{0, l.size() - 1};
    size_t offset = random_distribution(random_engine);
    return std::optional{std::next(l.begin(), static_cast<typename std::list<T>::iterator::difference_type>(offset))};
}

}  // namespace silkworm::sentry::common
