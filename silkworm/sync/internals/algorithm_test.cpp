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

#include "algorithm.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("move_at_end on vectors") {
    std::vector<int> source = {4, 5, 6};
    std::vector<int> destination = {1, 2, 3};

    move_at_end(destination, source);
    REQUIRE(source.size() == 3);  // source has elements but moved
    REQUIRE(destination.size() == 6);
    REQUIRE(destination == std::vector({1, 2, 3, 4, 5, 6}));
}

TEST_CASE("push_all on vectors") {
    std::vector<int> source = {4, 5, 6};
    std::stack<int> destination({1, 2, 3});

    push_all(destination, source);
    REQUIRE(source.size() == 3);
    REQUIRE(destination.size() == 6);
    REQUIRE(destination == std::stack<int>({1, 2, 3, 4, 5, 6}));
}

}  // namespace silkworm
