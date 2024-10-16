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

#include "bloom_filter.hpp"

#include <random>
#include <set>
#include <sstream>
#include <stdexcept>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

#include "../test_util/sample_bloom_filter_data.hpp"

namespace silkworm::snapshots::index {

TEST_CASE("BloomFilter", "[snapshot][index][bloom_filter]") {
    SECTION("empty") {
        CHECK_THROWS_AS(BloomFilter(0, 0.01), std::runtime_error);
    }

    SECTION("item present") {
        // Create PRNG to generate pseudo-random hash values
        static std::mt19937_64 rnd_generator{std::random_device{}()};
        std::uniform_int_distribution<uint32_t> u32_distribution;

        BloomFilter filter{BloomFilter::optimal_bits_count(10'000'000, 0.01)};
        CHECK(filter.key_count() == BloomFilter::kHardCodedK);
        CHECK(filter.bits_count() == BloomFilter::optimal_bits_count(10'000'000, 0.01));

        // Generate pseudo-random hash values and add them to the filter
        std::set<uint64_t> added_hashes;
        for (size_t i = 0; i < 100'000; ++i) {
            const uint64_t h = u32_distribution(rnd_generator);
            filter.add_hash(h);
            added_hashes.insert(h);
            CHECK(filter.contains_hash(h));  // maybe false positive but never incorrect
        }

        // Generate more pseudo-random hash values and if absent from filter assert not added
        for (size_t i = 0; i < 1'000'000; ++i) {
            const uint64_t h = u32_distribution(rnd_generator);
            if (!filter.contains_hash(h)) {  // definitely not present
                CHECK(!added_hashes.contains(h));
            }
        }
    }
}

TEST_CASE("BloomFilter: operator>>", "[snapshot][index][bloom_filter]") {
    BloomFilter filter;

    for (const auto& [hex_stream, description] : test_util::kInvalidBloomFilters) {
        SECTION("too short: " + std::string{description}) {
            const Bytes byte_stream = *from_hex(hex_stream);
            const std::string byte_stream_as_string{byte_stream.begin(), byte_stream.end()};
            std::istringstream input_stream{byte_stream_as_string};
            CHECK_THROWS_AS((input_stream >> filter), std::runtime_error);
        }
    }

    for (const auto hex_stream : test_util::kValidBloomFilters) {
        SECTION("valid: size=" + std::to_string(hex_stream.size())) {
            const Bytes byte_stream = *from_hex(hex_stream);
            const std::string byte_stream_as_string{byte_stream.begin(), byte_stream.end()};
            std::istringstream input_stream{byte_stream_as_string};
            CHECK_NOTHROW((input_stream >> filter));
            CHECK(filter.bits_count() == 2);
        }
    }
}

}  // namespace silkworm::snapshots::index
