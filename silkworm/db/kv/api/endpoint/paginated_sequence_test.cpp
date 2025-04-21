// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "paginated_sequence.hpp"

#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/test_util/context_test_base.hpp>
#include <silkworm/infra/test_util/fixture.hpp>

namespace silkworm::db::kv::api {

using namespace silkworm::test_util;

using PaginatedUint64 = PaginatedSequence<uint64_t>;
using PaginatorUint64 = PaginatedUint64::Paginator;
using PageUint64 = PaginatedUint64::Page;
using PageUint64List = std::vector<PageUint64>;
using PageResultUint64 = PaginatedUint64::PageResult;

using PaginatedKV = PaginatedSequencePair<Bytes, Bytes>;
using PaginatorKV = PaginatedKV::Paginator;
using PageK = PaginatedKV::KPage;
using PageV = PaginatedKV::VPage;
using PageResultKV = PaginatedKV::PageResult;

struct PaginatedSequenceTest : public test_util::ContextTestBase {
};

struct TestPaginatorUint64 {
    explicit TestPaginatorUint64(const PageUint64List& pages) : pages_(pages) {}

    Task<PageResultUint64> operator()(std::string /*page_token*/) {
        if (count_ == 0 && pages_.empty()) {
            co_return PageResultUint64{};
        }
        if (count_ < pages_.size()) {
            const auto next_token = (count_ != pages_.size() - 1) ? "next" : "";
            PageResultUint64 page_result{pages_[count_], next_token};
            ++count_;
            co_return page_result;
        }
        throw std::logic_error{"unexpected call to paginator"};
    }

  private:
    const PageUint64List& pages_;
    size_t count_{0};
};

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_uint64_sequence: empty sequence", "[db][kv][api][paginated_sequence]") {
    PageUint64List empty;
    TestPaginatorUint64 paginator{empty};

    PaginatedUint64 paginated{paginator};
    // We're using this lambda instead of built-in paginated_to_vector just to check Iterator::has_next
    const auto paginated_it_to_vector = [](auto& ps) -> Task<std::vector<uint64_t>> {
        auto it = co_await ps();
        CHECK(!co_await it->has_next());
        co_return co_await stream_to_vector(it);
    };
    CHECK(spawn_and_wait(paginated_it_to_vector(paginated)).empty());
}

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_uint64_sequence: non-empty sequence", "[db][kv][api][paginated_sequence]") {
    const Fixtures<PageUint64List, std::vector<uint64_t>> fixtures{
        {/*page_list=*/{}, /*expected_sequence=*/{}},
        {/*page_list=*/{{1}}, /*expected_sequence=*/{1}},
        {/*page_list=*/{{1, 2, 3}}, /*expected_sequence=*/{1, 2, 3}},
        {/*page_list=*/{{1, 2, 3}, {4, 5, 6}, {7}}, /*expected_sequence=*/{1, 2, 3, 4, 5, 6, 7}},
    };
    int i = 0;
    for (const auto& [page_list, expected_sequence] : fixtures) {
        SECTION("test vector: " + std::to_string(++i)) {
            TestPaginatorUint64 paginator{page_list};
            PaginatedUint64 paginated{paginator};
            CHECK(spawn_and_wait(paginated_to_vector(paginated)) == expected_sequence);
        }
    }
}

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_uint64_sequence: error", "[db][kv][api][paginated_sequence]") {
    PaginatorUint64 paginator = [](std::string) -> Task<PageResultUint64> {
        static int count{0};
        switch (++count) {
            case 1:
                co_return PageResultUint64{PageUint64{1, 2, 3}, "next"};
            case 2:
                co_return PageResultUint64{PageUint64{4, 5, 6}, "next"};
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
    PaginatorKV paginator = [](std::string) -> Task<PageResultKV> {
        co_return PageResultKV{};  // has_more=false as default
    };
    PaginatedKV paginated{paginator};
    // We're using this lambda instead of built-in paginated_to_vector just to check Iterator::has_next
    const auto paginated_it_to_vector = [](auto& ps) -> Task<std::vector<KeyValue>> {
        auto it = co_await ps();
        CHECK(!co_await it->has_next());
        co_return co_await stream_to_vector<PaginatedKV::KVPair, KeyValue>(it);
    };
    CHECK(spawn_and_wait(paginated_it_to_vector(paginated)).empty());
}

static const Bytes kKey1{*from_hex("0011")}, kKey2{*from_hex("0022")}, kKey3{*from_hex("0033")};
static const Bytes kKey4{*from_hex("0044")}, kKey5{*from_hex("0055")}, kKey6{*from_hex("0066")};

static const Bytes kValue1{*from_hex("FF11")}, kValue2{*from_hex("FF22")}, kValue3{*from_hex("FF33")};
static const Bytes kValue4{*from_hex("FF44")}, kValue5{*from_hex("FF55")}, kValue6{*from_hex("FF66")};

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_kv_sequence: non-empty sequence", "[db][kv][api][paginated_sequence]") {
    PaginatorKV paginator = [](std::string) -> Task<PageResultKV> {
        static int count{0};
        switch (++count) {
            case 1:
                co_return PageResultKV{PageK{kKey1, kKey2}, PageV{kValue1, kValue2}, "next"};
            case 2:
                co_return PageResultKV{PageK{kKey3, kKey4}, PageV{kValue3, kValue4}, "next"};
            case 3:
                co_return PageResultKV{PageK{kKey5, kKey6}, PageV{kValue5, kValue6}, ""};
            default:
                throw std::logic_error{"unexpected call to paginator"};
        }
    };
    PaginatedKV paginated{paginator};
    CHECK(spawn_and_wait(paginated_to_vector(paginated)) ==
          std::vector<KeyValue>{{kKey1, kValue1}, {kKey2, kValue2}, {kKey3, kValue3}, {kKey4, kValue4}, {kKey5, kValue5}, {kKey6, kValue6}});
}

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_kv_sequence: error", "[db][kv][api][paginated_sequence]") {
    PaginatorKV paginator = [](std::string) -> Task<PageResultKV> {
        static int count{0};
        switch (++count) {
            case 1:
                co_return PageResultKV{PageK{kKey1, kKey2}, PageV{kValue1, kValue2}, "next"};
            case 2:
                co_return PageResultKV{PageK{kKey3, kKey4}, PageV{kValue3, kValue4}, "next"};
            case 3:
                throw std::runtime_error{"error during pagination"};
            default:
                throw std::logic_error{"unexpected call to paginator"};
        }
    };
    PaginatedKV paginated{paginator};
    CHECK_THROWS_AS(spawn_and_wait(paginated_to_vector(paginated)), std::runtime_error);
}

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_uint64_sequence: set_intersection", "[db][kv][api][paginated_sequence]") {
    const Fixtures<std::pair<PageUint64List, PageUint64List>, std::vector<uint64_t>> fixtures{
        {{/*v1=*/{}, /*v2=*/{}}, /*v1_and_v2=*/{}},                                                // both empty => empty
        {{/*v1=*/{{1, 2, 3}, {4, 5, 6}, {7, 8}}, /*v2=*/{}}, /*v1_and_v2=*/{}},                    // one empty => empty
        {{/*v1=*/{{1, 2, 3}, {4, 5, 6}, {7, 8}}, /*v2=*/{{10, 11, 12}, {13}}}, /*v1_and_v2=*/{}},  // disjoint => empty
        {{/*v1=*/{{1, 2, 3}, {4, 5, 6}, {7, 8}}, /*v2=*/{{7, 8, 9}, {10, 11, 12}, {13}}}, /*v1_and_v2=*/{7, 8}},
        {{/*v1=*/{{1, 2, 3}, {4, 5, 6}, {7, 8}}, /*v2=*/{{1, 2, 3}, {4, 5, 6}, {7, 8}}}, /*v1_and_v2=*/{1, 2, 3, 4, 5, 6, 7, 8}},
    };
    int i = 0;
    for (const auto& [v1_v2_pair, expected_intersection_set] : fixtures) {
        const auto& [v1, v2] = v1_v2_pair;
        TestPaginatorUint64 paginator1{v1}, paginator2{v2};
        PaginatedUint64 paginated1{paginator1}, paginated2{paginator2};
        SECTION("test vector " + std::to_string(i)) {
            const auto async_intersection = [&](PaginatedUint64& ps1, PaginatedUint64& ps2) -> Task<std::vector<uint64_t>> {
                auto it = set_intersection(co_await ps1(), co_await ps2());
                CHECK(co_await it->has_next() == !expected_intersection_set.empty());
                co_return co_await stream_to_vector(it);
            };
            CHECK(spawn_and_wait(async_intersection(paginated1, paginated2)) == expected_intersection_set);
        }
        ++i;
    }
}

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_uint64_sequence: set_union", "[db][kv][api][paginated_sequence]") {
    const Fixtures<std::tuple<PageUint64List, PageUint64List, bool>, std::vector<uint64_t>> fixtures{
        /* ASCENDING */
        {{/*v1=*/{}, /*v2=*/{}, true}, /*v1_or_v2=*/{}},
        {{/*v1=*/{{1}}, /*v2=*/{}, true}, /*v1_or_v2=*/{1}},
        {{/*v1=*/{}, /*v2=*/{{1}}, true}, /*v1_or_v2=*/{1}},
        {{/*v1=*/{{1, 2, 3}, {4, 5, 6}, {7, 8}}, /*v2=*/{}, true}, /*v1_or_v2=*/{1, 2, 3, 4, 5, 6, 7, 8}},
        {{/*v1=*/{{1, 2, 3}, {4, 5, 6}, {7, 8}}, /*v2=*/{{10, 11, 12}, {13}}, true}, /*v1_or_v2=*/{1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13}},
        {{/*v1=*/{{1, 2, 3}, {4, 5, 6}, {7, 8}}, /*v2=*/{{7, 8, 9}, {10, 11, 12}, {13}}, true}, /*v1_or_v2=*/{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}},
        {{/*v1=*/{{1, 2, 3}, {4, 5, 6}, {7, 8}}, /*v2=*/{{1, 2, 3}, {4, 5, 6}, {7, 8}}, true}, /*v1_and_v2=*/{1, 2, 3, 4, 5, 6, 7, 8}},

        /* DESCENDING */
        {{/*v1=*/{}, /*v2=*/{}, false}, /*v1_or_v2=*/{}},
        {{/*v1=*/{{1}}, /*v2=*/{}, false}, /*v1_or_v2=*/{1}},
        {{/*v1=*/{}, /*v2=*/{{1}}, false}, /*v1_or_v2=*/{1}},
        {{/*v1=*/{{8, 7}, {6, 5, 4}, {3, 2, 1}}, /*v2=*/{}, false}, /*v1_or_v2=*/{8, 7, 6, 5, 4, 3, 2, 1}},
        {{/*v1=*/{{8, 7}, {6, 5, 4}, {3, 2, 1}}, /*v2=*/{{13}, {12, 11, 10}}, false}, /*v1_or_v2=*/{13, 12, 11, 10, 8, 7, 6, 5, 4, 3, 2, 1}},
    };
    int i = 0;
    for (const auto& [v1_v2_ascending, expected_union_set] : fixtures) {
        const auto& [v1, v2, ascending] = v1_v2_ascending;
        SECTION("test vector " + std::string{ascending ? "ascending" : "descending"} + ": " + std::to_string(i)) {
            TestPaginatorUint64 paginator1{v1}, paginator2{v2};
            PaginatedUint64 paginated1{paginator1}, paginated2{paginator2};
            const auto async_union = [&](PaginatedUint64& ps1, PaginatedUint64& ps2) -> Task<std::vector<uint64_t>> {
                auto it = set_union(co_await ps1(), co_await ps2(), ascending);
                CHECK(co_await it->has_next() == !expected_union_set.empty());
                co_return co_await stream_to_vector(it);
            };
            CHECK(spawn_and_wait(async_union(paginated1, paginated2)) == expected_union_set);
        }
        ++i;
    }
}

TEST_CASE_METHOD(PaginatedSequenceTest, "range stream", "[db][kv][api][paginated_sequence]") {
    const Fixtures<std::pair<uint64_t, uint64_t>, std::vector<uint64_t>> fixtures{
        {/*from, to=*/{0, 0}, /*expected_sequence=*/{}},
        {/*from, to=*/{0, 1}, /*expected_sequence=*/{0}},
        {/*from, tot=*/{0, 2}, /*expected_sequence=*/{0, 1}},
        {/*from, tot=*/{2, 0}, /*expected_sequence=*/{}}};
    int i = 0;
    for (const auto& [pair, expected_sequence] : fixtures) {
        SECTION("test range: " + std::to_string(++i)) {
            auto stream = make_range_stream<uint64_t>(pair.first, pair.second);
            auto sequence = spawn_and_wait(stream_to_vector(stream));
            CHECK(sequence == expected_sequence);
        }
    }
}

TEST_CASE_METHOD(PaginatedSequenceTest, "empty iterators", "[db][kv][api][paginated_sequence]") {
    EmptyIterator<uint64_t> empty_it_u64;
    CHECK_FALSE(spawn_and_wait(empty_it_u64.has_next()));
    CHECK(spawn_and_wait(empty_it_u64.next()) == std::nullopt);
    EmptyIterator<PaginatedKV::KVPair> empty_it_kv;
    CHECK(spawn_and_wait(empty_it_kv.next()) == std::nullopt);
}

struct TestPaginatorKV {
    explicit TestPaginatorKV(const std::vector<PageK>& k_pages, const std::vector<PageV>& v_pages)
        : k_pages_(k_pages), v_pages_(v_pages) {
        SILKWORM_ASSERT(k_pages_.size() == v_pages_.size());
    }

    Task<PageResultKV> operator()(std::string /*page_token*/) {
        if (count_ == 0 && k_pages_.empty()) {
            co_return PageResultKV{};
        }
        if (count_ < k_pages_.size()) {
            const auto next_token = (count_ != k_pages_.size() - 1) ? "next" : "";
            PageResultKV page_result{k_pages_[count_], v_pages_[count_], next_token};
            ++count_;
            co_return page_result;
        }
        throw std::logic_error{"unexpected call to paginator"};
    }

  private:
    const std::vector<PageK>& k_pages_;
    const std::vector<PageV>& v_pages_;
    size_t count_{0};
};

using KVPagesPair = std::pair<std::vector<PageK>, std::vector<PageV>>;

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_kv_sequence: set_union", "[db][kv][api][paginated_sequence]") {
    const Fixtures<std::tuple<KVPagesPair, KVPagesPair, bool>, std::vector<KeyValue>> fixtures{
        /* ASCENDING */
        {{/*v1=*/{{}, {}}, /*v2=*/{{}, {}}, true}, /*v1_or_v2=*/{}},
        {{/*v1=*/{/*k_pages=*/{{kKey1}}, /*v_pages=*/{{kValue1}}}, /*v2=*/{}, true}, /*v1_or_v2=*/{{kKey1, kValue1}}},
        {{/*v1=*/{/*k_pages=*/{{kKey1, kKey2}}, /*v_pages=*/{{kValue1, kValue2}}}, /*v2=*/{}, true}, /*v1_or_v2=*/{{kKey1, kValue1}, {kKey2, kValue2}}},
        {{/*v1=*/{}, /*v2=*/{/*k_pages=*/{{kKey1, kKey2}}, /*v_pages=*/{{kValue1, kValue2}}}, true}, /*v1_or_v2=*/{{kKey1, kValue1}, {kKey2, kValue2}}},

        /* DESCENDING */
        {{/*v1=*/{{}, {}}, /*v2=*/{{}, {}}, false}, /*v1_or_v2=*/{}},
        {{/*v1=*/{/*k_pages=*/{{kKey1}}, /*v_pages=*/{{kValue1}}}, /*v2=*/{}, false}, /*v1_or_v2=*/{{kKey1, kValue1}}},
        {{/*v1=*/{/*k_pages=*/{{kKey2, kKey1}}, /*v_pages=*/{{kValue2, kValue1}}}, /*v2=*/{}, false}, /*v1_or_v2=*/{{kKey2, kValue2}, {kKey1, kValue1}}},
        {{/*v1=*/{}, /*v2=*/{/*k_pages=*/{{kKey2, kKey1}}, /*v_pages=*/{{kValue2, kValue1}}}, false}, /*v1_or_v2=*/{{kKey2, kValue2}, {kKey1, kValue1}}},
    };
    int i = 0;
    for (const auto& [v1_v2_ascending, expected_union_set] : fixtures) {
        const auto& [v1, v2, ascending] = v1_v2_ascending;
        TestPaginatorKV paginator1{v1.first, v1.second}, paginator2{v2.first, v2.second};
        PaginatedKV paginated1{paginator1}, paginated2{paginator2};
        SECTION("test vector " + std::string{ascending ? "ascending" : "descending"} + ": " + std::to_string(i)) {
            const auto async_union = [&](PaginatedKV& ps1, PaginatedKV& ps2) -> Task<std::vector<KeyValue>> {
                auto it = set_union(co_await ps1(), co_await ps2(), ascending);
                CHECK(co_await it->has_next() == !expected_union_set.empty());
                co_return co_await stream_to_vector<PaginatedKV::KVPair, KeyValue>(it);
            };
            CHECK(spawn_and_wait(async_union(paginated1, paginated2)) == expected_union_set);
        }
        ++i;
    }
}

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_uint64_sequence: nested intersection", "[db][kv][api][paginated_sequence]") {
    SECTION("2 null streams") {
        Stream<uint64_t> n1;
        Stream<uint64_t> n2;
        const auto n1_n2_intersection = set_intersection(std::move(n1), std::move(n2));
        CHECK_FALSE(spawn_and_wait(n1_n2_intersection->has_next()));
        CHECK(spawn_and_wait(n1_n2_intersection->next()) == std::nullopt);
    }
    SECTION("2 empty streams") {
        Stream<uint64_t> e1 = std::make_unique<EmptyIterator<uint64_t>>();
        Stream<uint64_t> e2 = std::make_unique<EmptyIterator<uint64_t>>();
        const auto e1_e2_intersection = set_intersection(std::move(e1), std::move(e2));
        CHECK_FALSE(spawn_and_wait(e1_e2_intersection->has_next()));
        CHECK(spawn_and_wait(e1_e2_intersection->next()) == std::nullopt);
    }
    SECTION("1 empty stream 1 non-empty stream") {
        const auto async_union_with_empty = [&](PaginatedUint64& ps) -> Task<std::vector<uint64_t>> {
            Stream<uint64_t> empty = std::make_unique<EmptyIterator<uint64_t>>();
            auto stream = co_await ps();
            auto intersection_stream = set_intersection(std::move(stream), std::move(empty));
            co_return co_await stream_to_vector(intersection_stream);
        };
        PageUint64List v{{1, 2, 3}, {4, 5, 6}, {7, 8}};
        TestPaginatorUint64 paginator{v};
        PaginatedUint64 paginated{paginator};
        CHECK(spawn_and_wait(async_union_with_empty(paginated)).empty());
    }
    SECTION("nesting streams") {
        const auto nested_intersection = [&](std::vector<PaginatedUint64> ps_list) -> Task<std::vector<uint64_t>> {
            Stream<uint64_t> intersection_stream;
            for (auto& ps : ps_list) {
                intersection_stream = set_intersection(std::move(intersection_stream), co_await ps());
            }
            co_return co_await stream_to_vector(intersection_stream);
        };
        CHECK(spawn_and_wait(nested_intersection(std::vector<PaginatedUint64>{})).empty());
    }
}

TEST_CASE_METHOD(PaginatedSequenceTest, "paginated_uint64_sequence: nested unions", "[db][kv][api][paginated_sequence]") {
    SECTION("2 null streams") {
        Stream<uint64_t> n1;
        Stream<uint64_t> n2;
        const auto n1_n2_union = set_union(std::move(n1), std::move(n2));
        CHECK_FALSE(spawn_and_wait(n1_n2_union->has_next()));
        CHECK(spawn_and_wait(n1_n2_union->next()) == std::nullopt);
    }
    SECTION("2 empty streams") {
        Stream<uint64_t> e1 = std::make_unique<EmptyIterator<uint64_t>>();
        Stream<uint64_t> e2 = std::make_unique<EmptyIterator<uint64_t>>();
        const auto e1_e2_union = set_union(std::move(e1), std::move(e2));
        CHECK_FALSE(spawn_and_wait(e1_e2_union->has_next()));
        CHECK(spawn_and_wait(e1_e2_union->next()) == std::nullopt);
    }
    SECTION("1 empty stream 1 non-empty stream") {
        const auto async_union_with_empty = [&](PaginatedUint64& ps1) -> Task<std::vector<uint64_t>> {
            Stream<uint64_t> empty = std::make_unique<EmptyIterator<uint64_t>>();
            auto stream = co_await ps1();
            auto union_stream = set_union(std::move(stream), std::move(empty));
            co_return co_await stream_to_vector(union_stream);
        };
        PageUint64List v{{1, 2, 3}, {4, 5, 6}, {7, 8}};
        TestPaginatorUint64 paginator{v};
        PaginatedUint64 paginated{paginator};
        CHECK(spawn_and_wait(async_union_with_empty(paginated)) == std::vector<uint64_t>{1, 2, 3, 4, 5, 6, 7, 8});
    }
    SECTION("nesting streams") {
        const auto nested_union = [&](std::vector<PaginatedUint64> ps_list) -> Task<std::vector<uint64_t>> {
            Stream<uint64_t> union_stream;
            for (auto& ps : ps_list) {
                union_stream = set_union(std::move(union_stream), co_await ps());
            }
            co_return co_await stream_to_vector(union_stream);
        };
        CHECK(spawn_and_wait(nested_union(std::vector<PaginatedUint64>{})).empty());
    }
}

}  // namespace silkworm::db::kv::api
