/*
   Copyright 2022 The Silkrpc Authors

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

#include <cstddef>
#include <string>
#include <vector>

#include <catch2/catch.hpp>

#include <silkworm/silkrpc/test/context_test_base.hpp>

namespace silkrpc {

struct BinarySearchTest : test::ContextTestBase {
};

struct BinaryTestData {
    std::vector<std::size_t> sequence;
    std::size_t value;
    std::size_t result;
};

std::vector<BinaryTestData> kTestData = {
    {{}, 0, 0},
    {{}, 18, 0},
    {{1, 2, 6, 6, 7}, 0, 0},
    {{1, 2, 6, 6, 7}, 1, 0},
    {{1, 2, 6, 6, 7}, 2, 1},
    {{1, 2, 6, 6, 7}, 3, 2},
    {{1, 2, 6, 6, 7}, 4, 2},
    {{1, 2, 6, 6, 7}, 5, 2},
    {{1, 2, 6, 6, 7}, 6, 2},
    {{1, 2, 6, 6, 7}, 7, 4},
    {{1, 2, 6, 6, 7}, 8, 5},
    {{1, 2, 6, 6, 7}, 9, 5},
};

boost::asio::awaitable<std::size_t> binary_search_in_vector(std::vector<std::size_t> sequence, int value) {
    co_return co_await binary_search(sequence.size(), [&, value](uint64_t i) -> boost::asio::awaitable<bool> {
        co_return i < sequence.size() && sequence[i] >= value;
    });
}

TEST_CASE_METHOD(BinarySearchTest, "binary_search", "[silkrpc][common][binary_search]") {
    for (int i{0}; i < kTestData.size(); ++i) {
        const auto [s, v, r] = kTestData[i];
        SECTION("search" + std::to_string(i)) {
            CHECK_NOTHROW(spawn_and_wait(binary_search_in_vector(s, v)) == r);
        }
    }
}

} // namespace silkrpc
