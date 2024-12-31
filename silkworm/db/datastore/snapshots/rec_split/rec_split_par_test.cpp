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

#include "rec_split_par.hpp"

#include <iomanip>  // for std::setw and std::setfill
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/infra/test_util/temporary_file.hpp>

#include "test_util/xoroshiro128pp.hpp"

namespace silkworm::snapshots::rec_split {

using silkworm::test_util::TemporaryFile;
using test_util::next_pseudo_random;

// Exclude tests from Windows build due to access issues with files in OS temporary dir
#ifndef _WIN32

//! Make the MPHF predictable just for testing
static constexpr int kTestSalt{1};

TEST_CASE("RecSplit8-Par: key_count=0", "[silkworm][node][recsplit]") {
    TemporaryFile index_file;
    ThreadPool thread_pool{2};
    RecSplitSettings settings{
        .keys_count = 0,
        .bucket_size = 10,
        .index_path = index_file.path(),
        .base_data_id = 0};
    RecSplit8 rs{settings, par_build_strategy(thread_pool), /*.salt=*/kTestSalt};
    CHECK_THROWS_AS(rs.build(), std::logic_error);
    CHECK_THROWS_AS(rs("first_key"), std::logic_error);
}

TEST_CASE("RecSplit8-Par: key_count=1", "[silkworm][node][recsplit]") {
    TemporaryFile index_file;
    ThreadPool thread_pool{2};
    RecSplitSettings settings{
        .keys_count = 1,
        .bucket_size = 10,
        .index_path = index_file.path(),
        .base_data_id = 0};
    RecSplit8 rs{settings, par_build_strategy(thread_pool), /*.salt=*/kTestSalt};
    CHECK_NOTHROW(rs.add_key("first_key", 0));
    CHECK_NOTHROW(rs.build());
    CHECK_NOTHROW(rs("first_key"));
}

TEST_CASE("RecSplit8-Par key_count=2", "[silkworm][node][recsplit]") {
    TemporaryFile index_file;
    ThreadPool thread_pool{2};
    RecSplitSettings settings{
        .keys_count = 2,
        .bucket_size = 10,
        .index_path = index_file.path(),
        .base_data_id = 0};
    RecSplit8 rs{settings, par_build_strategy(thread_pool), /*.salt=*/kTestSalt};

    SECTION("keys") {
        CHECK_NOTHROW(rs.add_key("first_key", 0));
        CHECK_THROWS_AS(rs.build(), std::logic_error);
        CHECK_THROWS_AS(rs("first_key"), std::logic_error);
        CHECK_NOTHROW(rs.add_key("second_key", 0));
        CHECK(rs.build() == false /*collision_detected*/);
        CHECK_NOTHROW(rs("first_key"));
        CHECK_NOTHROW(rs("second_key"));
    }

    SECTION("duplicated keys") {
        CHECK_NOTHROW(rs.add_key("first_key", 0));
        CHECK_NOTHROW(rs.add_key("first_key", 0));
        CHECK(rs.build() == true /*collision_detected*/);
    }
}

template <typename RS>
static void check_bijection(RS& rec_split, const std::vector<Hash128>& keys) {
    // RecSplit implements a MPHF K={k1...kN} -> V={0..N-1} so we must check all codomain is exhausted
    std::vector<uint64_t> recsplit_values(keys.size());
    // Fill the codomain values w/ zero, so we can easily check if a value is already used or not
    std::fill(recsplit_values.begin(), recsplit_values.end(), 0);

    uint64_t i{0};
    for (const auto& k : keys) {
        uint64_t v = rec_split(k);
        // Value associated to key in RecSplit must be unique (perfect: no collision)
        CHECK(recsplit_values[v] == 0);
        // Mark the value as used in codomain
        recsplit_values[v] = ++i;
    }

    // All codomain values must be used (minimal: rank(K) == rank(V))
    for (const auto& v : recsplit_values) {
        CHECK(v != 0);
    }
}

static constexpr int kTestLeaf{4};

using RecSplit4 = RecSplit<kTestLeaf>;

template <>
const size_t RecSplit4::kLowerAggregationBound;
template <>
const size_t RecSplit4::kUpperAggregationBound;
template <>
const std::array<uint32_t, kMaxBucketSize> RecSplit4::kMemo;

auto par_build_strategy_4(ThreadPool& tp) { return std::make_unique<RecSplit4::ParallelBuildingStrategy>(tp); }

TEST_CASE("RecSplit4-Par: keys=1000 buckets=128", "[silkworm][node][recsplit]") {
    TemporaryFile index_file;
    ThreadPool thread_pool{2};

    constexpr int kTestNumKeys{1'000};
    constexpr int kTestBucketSize{128};

    std::vector<Hash128> hashed_keys;
    for (size_t i{0}; i < kTestNumKeys; ++i) {
        hashed_keys.push_back({next_pseudo_random(), next_pseudo_random()});
    }

    RecSplitSettings settings{
        .keys_count = hashed_keys.size(),
        .bucket_size = kTestBucketSize,
        .index_path = index_file.path(),
        .base_data_id = 0};
    RecSplit4 rs{settings, par_build_strategy_4(thread_pool), /*.salt=*/kTestSalt};

    SECTION("random_hash128 KO: not built") {
        for (const auto& hk : hashed_keys) {
            rs.add_key(hk, 0);
        }
        // RecSplit not built implies operator() must raise an exception
        for (const auto& hk : hashed_keys) {
            CHECK_THROWS_AS(rs(hk), std::logic_error);
        }
    }

    SECTION("random_hash128 OK") {
        for (const auto& hk : hashed_keys) {
            rs.add_key(hk, 0);
        }
        CHECK(rs.build() == false /*collision_detected*/);
        check_bijection(rs, hashed_keys);
    }
}

TEST_CASE("RecSplit4-Par: multiple keys-buckets", "[silkworm][node][recsplit]") {
    TemporaryFile index_file;
    ThreadPool thread_pool{2};

    struct RecSplitParams {
        size_t key_count{0};
        uint16_t bucket_size{0};
    };
    std::vector<RecSplitParams> recsplit_params_sequence{
        {1'000, 128},
        {5'000, 512},
        {10'000, 1024},
        {20'000, 2048},
        {40'000, 2048},
    };
    for (const auto [key_count, bucket_size] : recsplit_params_sequence) {
        SECTION("random_hash128 OK [" + std::to_string(key_count) + "-" + std::to_string(bucket_size) + "]") {  // NOLINT
            std::vector<Hash128> hashed_keys;
            for (size_t i{0}; i < key_count; ++i) {
                hashed_keys.push_back({next_pseudo_random(), next_pseudo_random()});
            }

            RecSplitSettings settings{
                .keys_count = key_count,
                .bucket_size = bucket_size,
                .index_path = index_file.path(),
                .base_data_id = 0};
            RecSplit4 rs{settings, par_build_strategy_4(thread_pool), /*.salt=*/kTestSalt};

            for (const auto& hk : hashed_keys) {
                rs.add_key(hk, 0);
            }
            CHECK(rs.build() == false /*collision_detected*/);
            check_bijection(rs, hashed_keys);

            RecSplit4 rs_index{index_file.path()};
            CHECK(rs.base_data_id() == settings.base_data_id);
            CHECK(rs.key_count() == settings.keys_count);
            CHECK(rs.empty() == !settings.keys_count);
            CHECK(rs.record_mask() == 0);
            CHECK(rs.bucket_count() == (settings.keys_count + settings.bucket_size - 1) / settings.bucket_size);
            CHECK(rs.bucket_size() == settings.bucket_size);
            check_bijection(rs_index, hashed_keys);
        }
    }
}

#ifdef SILKWORM_TEST_SKIP
TEST_CASE("RecSplit8-Par: index lookup", "[silkworm][node][recsplit]") {
    TemporaryFile index_file;
    ThreadPool thread_pool{2};
    RecSplitSettings settings{
        .keys_count = 100,
        .bucket_size = 10,
        .index_path = index_file.path(),
        .base_data_id = 0,
        .double_enum_index = false};
    RecSplit8 rs1{settings, par_build_strategy(thread_pool), /*.salt=*/kTestSalt};

    for (size_t i{0}; i < settings.keys_count; ++i) {
        rs1.add_key("key " + std::to_string(i), i * 17);
    }
    CHECK(rs1.build() == false /*collision_detected*/);

    RecSplit8 rs2{settings.index_path};
    for (size_t i{0}; i < settings.keys_count; ++i) {
        const std::string key{"key " + std::to_string(i)};
        CHECK(rs2.lookup(key) == RecSplit8::LookupResult{i * 17, true});
    }
}
#endif  // SILKWORM_TEST_SKIP

#ifdef SILKWORM_TEST_SKIP
TEST_CASE("RecSplit8-Par: double index lookup", "[silkworm][node][recsplit]") {
    TemporaryFile index_file;
    ThreadPool thread_pool{2};
    RecSplitSettings settings{
        .keys_count = 100,
        .bucket_size = 10,
        .index_path = index_file.path(),
        .base_data_id = 0};
    RecSplit8 rs1{settings, par_build_strategy(thread_pool), /*.salt=*/kTestSalt};

    for (size_t i{0}; i < settings.keys_count; ++i) {
        rs1.add_key("key " + std::to_string(i), i * 17);
    }
    CHECK(rs1.build() == false /*collision_detected*/);

    RecSplit8 rs2{settings.index_path};
    for (size_t i{0}; i < settings.keys_count; ++i) {
        const auto enumeration_index = rs2.lookup_ordinal_by_key("key " + std::to_string(i));
        REQUIRE(enumeration_index);
        CHECK(enumeration_index == i);
        CHECK(rs2.lookup_by_ordinal(enumeration_index) == i * 17);
    }
}
#endif

#endif  // _WIN32

}  // namespace silkworm::snapshots::rec_split