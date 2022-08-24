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

#include "random.hpp"

#include <random>

namespace silkworm::sentry::common {

Bytes random_bytes(Bytes::size_type size) {
    std::default_random_engine random_engine{std::random_device{}()};
    std::uniform_int_distribution<uint16_t> random_distribution{0, UINT8_MAX};

    Bytes data(size, 0);
    for (auto& d : data) {
        d = random_distribution(random_engine);
    }
    return data;
}

}  // namespace silkworm::sentry::common
