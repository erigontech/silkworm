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

#include "async_binary_search.hpp"

#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/context_test_base.hpp>

namespace silkworm {

struct BinarySearchTest : test_util::ContextTestBase {
};

struct BinaryTestData {
    std::vector<size_t> sequence;
    size_t value;
    size_t result;
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

Task<size_t> binary_search_in_vector(std::vector<size_t> sequence, size_t value) {
    co_return co_await async_binary_search(sequence.size(), [&, value](uint64_t i) -> Task<bool> {
        co_return i < sequence.size() && sequence[i] >= value;
    });
}

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(BinarySearchTest, "binary_search", "[infra][common][binary_search]") {
    for (size_t i{0}; i < kTestData.size(); ++i) {
        const auto [s, v, r] = kTestData[i];
        SECTION("search" + std::to_string(i)) {
            CHECK_NOTHROW(spawn_and_wait(binary_search_in_vector(s, v)) == r);
        }
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm
