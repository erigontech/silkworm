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

#include "rec_split.hpp"

#include <cstdint>
#include <vector>

#include <catch2/catch.hpp>

#include <silkworm/test/files.hpp>
#include <silkworm/test/log.hpp>
#include <silkworm/test/xoroshiro128pp.hpp>

namespace silkworm::succinct {

//! Make the MPHF predictable just for testing
constexpr int kTestSalt{1};

TEST_CASE("RecSplit8", "[silkworm][recsplit]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    test::TemporaryFile index_file;

    SECTION("keys") {
        RecSplit8 rs{
            /*.keys_count=*/2,
            /*.bucket_size=*/10,
            /*.index_path=*/index_file.path(),
            /*.base_data_id=*/0,
            /*.salt=*/kTestSalt,
        };
        CHECK_NOTHROW(rs.add_key("first_key", 0));
        CHECK_THROWS_AS(rs.build(), std::logic_error);
        CHECK_NOTHROW(rs.add_key("second_key", 0));
        CHECK_NOTHROW(rs.build());
    }

    SECTION("duplicated keys") {
        RecSplit8 rs{
            /*.keys_count=*/2,
            /*.bucket_size=*/10,
            /*.index_path=*/index_file.path(),
            /*.base_data_id=*/0,
            /*.salt=*/kTestSalt,
        };
        CHECK_NOTHROW(rs.add_key("first_key", 0));
        CHECK_NOTHROW(rs.add_key("first_key", 0));
        CHECK(rs.build() == true /*collision_detected*/);
    }
}

template <typename RS>
static void check_bijection(RS& rec_split, const std::vector<hash128_t>& keys) {
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

constexpr int kTestLeaf{4};

using RecSplit4 = RecSplit<kTestLeaf>;
template <>
const std::size_t RecSplit4::kLowerAggregationBound = RecSplit4::SplitStrategy::kLowerAggregationBound;
template <>
const std::size_t RecSplit4::kUpperAggregationBound = RecSplit4::SplitStrategy::kUpperAggregationBound;
template <>
const std::array<uint32_t, kMaxBucketSize> RecSplit4::memo = RecSplit4::fill_golomb_rice();

TEST_CASE("RecSplit4: keys=1000 buckets=128", "[silkworm][recsplit]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    test::TemporaryFile index_file;

    constexpr int kTestNumKeys{1'000};
    constexpr int kTestBucketSize{128};

    std::vector<hash128_t> hashed_keys;
    for (std::size_t i{0}; i < kTestNumKeys; ++i) {
        hashed_keys.push_back({test::next_pseudo_random(), test::next_pseudo_random()});
    }

    RecSplit4 rs{
        /*.keys_count=*/hashed_keys.size(),
        /*.bucket_size=*/kTestBucketSize,
        /*.index_path=*/index_file.path(),
        /*.base_data_id=*/0,
        /*.salt=*/kTestSalt,
    };

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

TEST_CASE("RecSplit4: multiple keys-buckets", "[silkworm][recsplit]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    test::TemporaryFile index_file;

    struct RecSplitParams {
        std::size_t key_count{0};
        std::size_t bucket_size{0};
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
            std::vector<hash128_t> hashed_keys;
            for (std::size_t i{0}; i < key_count; ++i) {
                hashed_keys.push_back({test::next_pseudo_random(), test::next_pseudo_random()});
            }

            RecSplit4 rs{
                /*.keys_count=*/hashed_keys.size(),
                /*.bucket_size=*/bucket_size,
                /*.index_path=*/index_file.path(),
                /*.base_data_id=*/0,
                /*.salt=*/kTestSalt,
            };

            for (const auto& hk : hashed_keys) {
                rs.add_key(hk, 0);
            }
            CHECK(rs.build() == false /*collision_detected*/);
            check_bijection(rs, hashed_keys);
        }
    }
}

}  // namespace silkworm::succinct
