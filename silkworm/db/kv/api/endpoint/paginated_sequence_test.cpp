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

#include "paginated_sequence.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/context_test_base.hpp>

namespace silkworm::db::kv::api {

using PaginatedUint64 = PaginatedSequence<uint64_t>;

struct PaginatedSequenceTest : public test_util::ContextTestBase {
};

template <typename T>
Task<std::vector<T>> to_vector(PaginatedSequence<T>& paginated) {
    std::vector<T> all_values;
    auto it = co_await paginated.begin();
    while (it != paginated.end()) {
        all_values.emplace_back(*it);
        co_await ++it;
    }
    co_return all_values;
}

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_sequence: empty uint64 sequence", "[db][kv][api][paginated_sequence]") {
    PaginatedUint64::Paginator paginator = []() -> Task<PaginatedUint64::PageResult> {
        co_return PaginatedUint64::PageResult{};  // has_more=false as default
    };
    PaginatedUint64 paginated{paginator};
    CHECK(spawn_and_wait(to_vector(paginated)).empty());
}

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_sequence: non-empty uint64 sequence", "[db][kv][api][paginated_sequence]") {
    PaginatedUint64::Paginator paginator = []() -> Task<PaginatedUint64::PageResult> {
        static int count{0};
        switch (++count) {
            case 1:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{1, 2, 3}, /*has_more=*/true};
            case 2:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{4, 5, 6}, /*has_more=*/true};
            case 3:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{7}, /*has_more=*/false};
            default:
                throw std::logic_error{"unexpected call to paginator"};
        }
    };
    PaginatedUint64 paginated{paginator};
    CHECK(spawn_and_wait(to_vector(paginated)) == std::vector<uint64_t>{1, 2, 3, 4, 5, 6, 7});
}

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_sequence: error", "[db][kv][api][paginated_sequence]") {
    PaginatedUint64::Paginator paginator = []() -> Task<PaginatedUint64::PageResult> {
        static int count{0};
        switch (++count) {
            case 1:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{1, 2, 3}, /*has_more=*/true};
            case 2:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{4, 5, 6}, /*has_more=*/true};
            case 3:
                throw std::runtime_error{"error during pagination"};
            default:
                throw std::logic_error{"unexpected call to paginator"};
        }
    };
    PaginatedUint64 paginated{paginator};
    CHECK_THROWS_AS(spawn_and_wait(to_vector(paginated)), std::runtime_error);
}

}  // namespace silkworm::db::kv::api
