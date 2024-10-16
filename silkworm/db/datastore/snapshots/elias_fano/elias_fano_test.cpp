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

#include "elias_fano.hpp"

#include <algorithm>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::snapshots::elias_fano {

using silkworm::snapshots::encoding::Uint64Sequence;

struct EliasFanoList32Test {
    std::vector<uint64_t> offsets;
    uint64_t expected_u;
    Uint64Sequence expected_data;
};

static std::string le_hex(uint64_t value) {
    uint8_t full_be[sizeof(uint64_t)];
    endian::store_little_u64(full_be, value);
    return to_hex(full_be);
}

static std::string be_hex(uint64_t value) {
    uint8_t full_be[sizeof(uint64_t)];
    endian::store_big_u64(full_be, value);
    return to_hex(full_be);
}

static std::string hex(const Uint64Sequence& value_sequence) {
    std::string hex;
    for (const auto value : value_sequence) {
        hex += le_hex(value);
    }
    return hex;
}

static std::string to_expected_hex(uint64_t count, uint64_t u, const Uint64Sequence& data) {
    return be_hex(count) + be_hex(u) + hex(data);
}

static std::vector<uint64_t> generate_contiguous_offsets(uint64_t count) {
    std::vector<uint64_t> offsets;
    offsets.reserve(count);
    for (size_t i{0}; i < count; ++i) {
        offsets.push_back(i);
    }
    return offsets;
}

TEST_CASE("EliasFanoList32", "[silkworm][recsplit][elias_fano]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};

    std::vector<EliasFanoList32Test> ef_test_vector{
        // Test Pattern 1
        {
            {1, 4, 6, 8, 10, 14, 16, 19, 22, 34, 37, 39, 41, 43, 48, 51, 54, 58, 62},  // offsets
            0x3f,                                                                      // u
            {0xbc81, 0x0, 0x24945540952a9, 0x0, 0x0, 0x0},                             // data
        },

        // Test Pattern 2
        {
            {1, 4, 14'800'000'000'000'000},                                                   // offsets
            0x0034948586ad0001,                                                               // u
            {18'014'398'509'481'985, 12'465'963'768'561'532'928u, 76842374, 0, 35, 0, 0, 0},  // data
        },

        // Test Pattern 3 [mask uint32 overflow (i>256)]
        {
            generate_contiguous_offsets(260),  // offsets
            260,                               // u
            {0, 0x5555555555555555, 0x5555555555555555, 0x5555555555555555, 0x5555555555555555, 0x5555555555555555,
             0x5555555555555555, 0x5555555555555555, 0x5555555555555555, 85, 0, 0x20000000000, 0},  // data
        },
    };
    for (const auto& ef_test : ef_test_vector) {
        // Encode monotone ascending integer sequence using Elias-Fano representation
        const uint64_t max_offset = *std::max_element(ef_test.offsets.cbegin(), ef_test.offsets.cend());
        EliasFanoList32 ef_list{ef_test.offsets.size(), max_offset};
        for (const auto offset : ef_test.offsets) {
            ef_list.add_offset(offset);
        }
        ef_list.build();

        CHECK(ef_list.min() == ef_test.offsets.at(0));
        CHECK(ef_list.max() == max_offset);
        CHECK(ef_list.count() == ef_test.offsets.size() - 1);
        CHECK(ef_list.sequence_length() == ef_test.offsets.size());

        for (uint64_t i{0}; i < ef_test.offsets.size(); ++i) {
            const uint64_t x = ef_list.get(i);
            CHECK(x == ef_test.offsets[i]);
        }

        CHECK(ef_list.data() == ef_test.expected_data);

        std::stringstream str_stream;
        str_stream << ef_list;
        const std::string stream = str_stream.str();
        Bytes ef_bytes{stream.cbegin(), stream.cend()};
        CHECK(to_hex(ef_bytes) == to_expected_hex(ef_test.offsets.size() - 1, ef_test.expected_u, ef_test.expected_data));

        // Decode monotone ascending integer sequence from Elias-Fano representation and compare with original
        constexpr size_t kParamsSize{2 * sizeof(uint64_t)};  // count + u length in bytes
        std::span<uint8_t> data{ef_bytes.data() + kParamsSize, ef_bytes.size() - kParamsSize};
        EliasFanoList32 ef_list_copy{ef_test.offsets.size() - 1, ef_test.expected_u, data};
        for (uint64_t i{0}; i < ef_test.offsets.size(); ++i) {
            const uint64_t x = ef_list_copy.get(i);
            CHECK(x == ef_test.offsets[i]);
        }
    }
}

TEST_CASE("DoubleEliasFanoList16", "[silkworm][recsplit][elias_fano]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    DoubleEliasFanoList16 double_ef_list;
    std::vector<uint64_t> cum_keys{1, 1, 2, 6, 7, 11, 13, 20};
    std::vector<uint64_t> position{1, 2, 5, 5, 6, 7, 9, 9};
    double_ef_list.build(cum_keys, position);

    CHECK(double_ef_list.num_buckets() == cum_keys.size() - 1);

    for (uint64_t i{0}; i < double_ef_list.num_buckets(); ++i) {
        uint64_t x{0}, x2{0}, y{0};

        double_ef_list.get3(i, x, x2, y);
        CHECK(x == cum_keys[i]);
        CHECK(x2 == cum_keys[i + 1]);
        CHECK(y == position[i]);

        double_ef_list.get2(i, x, y);
        CHECK(x == cum_keys[i]);
        CHECK(y == position[i]);
    }

    CHECK(double_ef_list.data() == Uint64Sequence{0x73, 0x0, 0x214cb, 0x1958a, 0x0, 0x1, 0x0, 0x0});

    std::stringstream str_stream;
    str_stream << double_ef_list;
    const std::string stream = str_stream.str();
    CHECK(Bytes{stream.cbegin(), stream.cend()} ==
          *from_hex("0000000000000007"  // num_buckets
                    "0000000000000015"  // u_cum_keys
                    "000000000000000a"  // u_position
                    "0000000000000000"  // cum_keys_min_delta
                    "0000000000000000"  // position_min_delta
                    "73000000000000000000000000000000cb140200000000008a95010000000000"
                    "0000000000000000010000000000000000000000000000000000000000000000"));
}

}  // namespace silkworm::snapshots::elias_fano
