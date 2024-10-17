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

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/test_util/context_test_base.hpp>

namespace silkworm::db::kv::api {

using PaginatedUint64 = PaginatedSequence<uint64_t>;
using PaginatorUint64 = PaginatedUint64::Paginator;
using PageUint64 = PaginatedUint64::Page;
using PageResultUint64 = PaginatedUint64::PageResult;

using PaginatedKV = PaginatedSequencePair<Bytes, Bytes>;
using PaginatorKV = PaginatedKV::Paginator;
using PageK = PaginatedKV::KPage;
using PageV = PaginatedKV::VPage;
using PageResultKV = PaginatedKV::PageResult;

struct PaginatedSequenceTest : public test_util::ContextTestBase {
};

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_uint64_sequence: empty sequence", "[db][kv][api][paginated_sequence]") {
    PaginatorUint64 paginator = []() -> Task<PageResultUint64> {
        co_return PageResultUint64{};  // has_more=false as default
    };
    PaginatedUint64 paginated{paginator};
    CHECK(spawn_and_wait(paginated_to_vector(paginated)).empty());
}

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_uint64_sequence: non-empty sequence", "[db][kv][api][paginated_sequence]") {
    PaginatorUint64 paginator = []() -> Task<PageResultUint64> {
        static int count{0};
        switch (++count) {
            case 1:
                co_return PageResultUint64{PageUint64{1, 2, 3}, /*has_more=*/true};
            case 2:
                co_return PageResultUint64{PageUint64{4, 5, 6}, /*has_more=*/true};
            case 3:
                co_return PageResultUint64{PageUint64{7}, /*has_more=*/false};
            default:
                throw std::logic_error{"unexpected call to paginator"};
        }
    };
    PaginatedUint64 paginated{paginator};
    CHECK(spawn_and_wait(paginated_to_vector(paginated)) == std::vector<uint64_t>{1, 2, 3, 4, 5, 6, 7});
}

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_uint64_sequence: error", "[db][kv][api][paginated_sequence]") {
    PaginatorUint64 paginator = []() -> Task<PageResultUint64> {
        static int count{0};
        switch (++count) {
            case 1:
                co_return PageResultUint64{PageUint64{1, 2, 3}, /*has_more=*/true};
            case 2:
                co_return PageResultUint64{PageUint64{4, 5, 6}, /*has_more=*/true};
            case 3:
                throw std::runtime_error{"error during pagination"};
            default:
                throw std::logic_error{"unexpected call to paginator"};
        }
    };
    PaginatedUint64 paginated{paginator};
    CHECK_THROWS_AS(spawn_and_wait(paginated_to_vector(paginated)), std::runtime_error);
}

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_kv_sequence: empty sequence", "[db][kv][api][paginated_sequence]") {
    PaginatorKV paginator = []() -> Task<PageResultKV> {
        co_return PageResultKV{};  // has_more=false as default
    };
    PaginatedKV paginated{paginator};
    CHECK(spawn_and_wait(paginated_to_vector(paginated)).empty());
}

const Bytes kKey1{*from_hex("0011")}, kKey2{*from_hex("0022")}, kKey3{*from_hex("0033")};
const Bytes kKey4{*from_hex("0044")}, kKey5{*from_hex("0055")}, kKey6{*from_hex("0066")};

const Bytes kValue1{*from_hex("FF11")}, kValue2{*from_hex("FF22")}, kValue3{*from_hex("FF33")};
const Bytes kValue4{*from_hex("FF44")}, kValue5{*from_hex("FF55")}, kValue6{*from_hex("FF66")};

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_kv_sequence: non-empty sequence", "[db][kv][api][paginated_sequence]") {
    PaginatorKV paginator = []() -> Task<PageResultKV> {
        static int count{0};
        switch (++count) {
            case 1:
                co_return PageResultKV{PageK{kKey1, kKey2}, PageV{kValue1, kValue2}, /*has_more=*/true};
            case 2:
                co_return PageResultKV{PageK{kKey3, kKey4}, PageV{kValue3, kValue4}, /*has_more=*/true};
            case 3:
                co_return PageResultKV{PageK{kKey5, kKey6}, PageV{kValue5, kValue6}, /*has_more=*/false};
            default:
                throw std::logic_error{"unexpected call to paginator"};
        }
    };
    PaginatedKV paginated{paginator};
    CHECK(spawn_and_wait(paginated_to_vector(paginated)) == std::vector<KeyValue>{
                                                                {kKey1, kValue1}, {kKey2, kValue2}, {kKey3, kValue3}, {kKey4, kValue4}, {kKey5, kValue5}, {kKey6, kValue6}});
}

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_kv_sequence: error", "[db][kv][api][paginated_sequence]") {
    PaginatorKV paginator = []() -> Task<PageResultKV> {
        static int count{0};
        switch (++count) {
            case 1:
                co_return PageResultKV{PageK{kKey1, kKey2}, PageV{kValue1, kValue2}, /*has_more=*/true};
            case 2:
                co_return PageResultKV{PageK{kKey3, kKey4}, PageV{kValue3, kValue4}, /*has_more=*/true};
            case 3:
                throw std::runtime_error{"error during pagination"};
            default:
                throw std::logic_error{"unexpected call to paginator"};
        }
    };
    PaginatedKV paginated{paginator};
    CHECK_THROWS_AS(spawn_and_wait(paginated_to_vector(paginated)), std::runtime_error);
}

struct PaginatedSetTest : public test_util::ContextTestBase {
};

TEST_CASE_METHOD(PaginatedSetTest, "set_intersection: non-empty uint64 sequence", "[db][kv][api][paginated_sequence]") {
    PaginatedUint64::Paginator paginator1 = []() -> Task<PaginatedUint64::PageResult> {
        static int count{0};
        switch (++count) {
            case 1:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{1, 2, 3}, /*has_more=*/true};
            case 2:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{4, 5, 6}, /*has_more=*/true};
            case 3:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{7, 8}, /*has_more=*/false};
            default:
                throw std::logic_error{"unexpected call to paginator"};
        }
    };
    PaginatedUint64::Paginator paginator2 = []() -> Task<PaginatedUint64::PageResult> {
        static int count{0};
        switch (++count) {
            case 1:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{7, 8, 9}, /*has_more=*/true};
            case 2:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{10, 11, 12}, /*has_more=*/true};
            case 3:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{13}, /*has_more=*/false};
            default:
                throw std::logic_error{"unexpected call to paginator"};
        }
    };
    PaginatedUint64 paginated1{paginator1}, paginated2{paginator2};
    const auto async_intersection = [](PaginatedUint64& ps1, PaginatedUint64& ps2) -> Task<std::vector<uint64_t>> {
        IntersectionIterator it = set_intersection(co_await ps1.begin(), co_await ps2.begin());
        co_return co_await paginated_iterator_to_vector(std::move(it));
    };
    CHECK(spawn_and_wait(async_intersection(paginated1, paginated2)) == std::vector<uint64_t>{7, 8});
}

TEST_CASE_METHOD(PaginatedSetTest, "set_union: non-empty uint64 sequence", "[db][kv][api][paginated_sequence]") {
    PaginatedUint64::Paginator paginator1 = []() -> Task<PaginatedUint64::PageResult> {
        static int count{0};
        switch (++count) {
            case 1:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{1, 2, 3}, /*has_more=*/true};
            case 2:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{4, 5, 6}, /*has_more=*/true};
            case 3:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{7, 8}, /*has_more=*/false};
            default:
                throw std::logic_error{"unexpected call to paginator"};
        }
    };
    PaginatedUint64::Paginator paginator2 = []() -> Task<PaginatedUint64::PageResult> {
        static int count{0};
        switch (++count) {
            case 1:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{7, 8, 9}, /*has_more=*/true};
            case 2:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{10, 11, 12}, /*has_more=*/true};
            case 3:
                co_return PaginatedUint64::PageResult{PaginatedUint64::Page{13}, /*has_more=*/false};
            default:
                throw std::logic_error{"unexpected call to paginator"};
        }
    };
    PaginatedUint64 paginated1{paginator1}, paginated2{paginator2};
    const auto async_intersection = [](PaginatedUint64& ps1, PaginatedUint64& ps2) -> Task<std::vector<uint64_t>> {
        UnionIterator<PaginatedUint64::Iterator> it = set_union(co_await ps1.begin(), co_await ps2.begin());
        co_return co_await paginated_iterator_to_vector(std::move(it));
    };
    CHECK(spawn_and_wait(async_intersection(paginated1, paginated2)) == std::vector<uint64_t>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13});
}

}  // namespace silkworm::db::kv::api
