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

#include "config_map.hpp"

#include <catch2/catch.hpp>

namespace silkworm {

TEST_CASE("ConfigMap value") {
    static constexpr ConfigMap<uint64_t> config{{10, 16}, {0, 64}, {20, 12}};

    static_assert(config.value(0) == 64);
    static_assert(config.value(1) == 64);
    static_assert(config.value(9) == 64);
    static_assert(config.value(10) == 16);
    static_assert(config.value(11) == 16);
    static_assert(config.value(19) == 16);
    static_assert(config.value(20) == 12);
    static_assert(config.value(21) == 12);
    static_assert(config.value(100) == 12);
}

}  // namespace silkworm
