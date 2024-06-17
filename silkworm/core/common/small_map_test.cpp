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

#include "small_map.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("SmallMap find") {
    static constexpr SmallMap<int, double> config{{20, 20.20}, {10, 10.10}, {30, 30.30}};
    static_assert(!config.find(0));
    static_assert(*config.find(10) == 10.10);
    static_assert(!config.find(15));
    static_assert(*config.find(20) == 20.20);
    static_assert(!config.find(25));
    static_assert(*config.find(30) == 30.30);
    static_assert(!config.find(100));
}

TEST_CASE("SmallMap to_std_map") {
    static constexpr SmallMap<int, double> small_map{{20, 20.20}, {10, 10.10}, {30, 30.30}};
    static const std::map<int, double> std_map{{20, 20.20}, {10, 10.10}, {30, 30.30}};
    CHECK(small_map.to_std_map() == std_map);
}

}  // namespace silkworm
