// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "elias_fano_list.hpp"

#include <algorithm>
#include <span>
#include <sstream>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>

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

static EliasFanoList32Builder make_list(const std::vector<uint64_t>& offsets) {
    const uint64_t max_offset = *std::max_element(offsets.cbegin(), offsets.cend());
    EliasFanoList32Builder list{offsets.size(), max_offset};
    for (uint64_t offset : offsets) {
        list.add_offset(offset);
    }
    list.build();
    return list;
}

TEST_CASE("EliasFanoList32", "[silkworm][recsplit][elias_fano]") {
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
        EliasFanoList32Builder ef_list_builder = make_list(ef_test.offsets);
        EliasFanoList32 ef_list = ef_list_builder.as_view();

        CHECK(ef_list.min() == ef_test.offsets.at(0));
        CHECK(ef_list.max() == max_offset);
        CHECK(ef_list.size() == ef_test.offsets.size());

        for (uint64_t i{0}; i < ef_test.offsets.size(); ++i) {
            const uint64_t x = ef_list.at(i);
            CHECK(x == ef_test.offsets[i]);
        }

        CHECK(std::ranges::equal(ef_list.data(), ef_test.expected_data));

        std::stringstream str_stream;
        str_stream << ef_list;
        const std::string stream = str_stream.str();
        Bytes ef_bytes{stream.cbegin(), stream.cend()};
        CHECK(to_hex(ef_bytes) == to_expected_hex(ef_test.offsets.size() - 1, ef_test.expected_u, ef_test.expected_data));

        // Decode monotone ascending integer sequence from Elias-Fano representation and compare with original
        EliasFanoList32 ef_list_copy = EliasFanoList32::from_encoded_data(ef_bytes);
        for (uint64_t i{0}; i < ef_test.offsets.size(); ++i) {
            const uint64_t x = ef_list_copy.at(i);
            CHECK(x == ef_test.offsets[i]);
        }
    }
}

static_assert(IndexedListConcept<const EliasFanoList32>);
static_assert(std::ranges::random_access_range<const EliasFanoList32>);

TEST_CASE("EliasFanoList32::seek", "[silkworm][recsplit][elias_fano]") {
    using SeekResult = std::pair<size_t, uint64_t>;
    std::vector<uint64_t> offsets = {1, 4, 6, 8, 10, 14, 16, 19, 22, 34, 37, 39, 41, 43, 48, 51, 54, 58, 62};
    EliasFanoList32Builder ef_list_builder = make_list(offsets);
    EliasFanoList32 ef_list = ef_list_builder.as_view();

    // seek forward
    CHECK(ef_list.seek(0) == SeekResult{0, 1});
    CHECK(ef_list.seek(1) == SeekResult{0, 1});
    CHECK(ef_list.seek(2) == SeekResult{1, 4});
    CHECK(ef_list.seek(4) == SeekResult{1, 4});
    CHECK(ef_list.seek(20) == SeekResult{8, 22});
    CHECK(ef_list.seek(62) == SeekResult{offsets.size() - 1, 62});
    CHECK_FALSE(ef_list.seek(70).has_value());

    // seek reverse
    CHECK_FALSE(ef_list.seek(0, true).has_value());
    CHECK(ef_list.seek(1, true) == SeekResult{0, 1});
    CHECK(ef_list.seek(2, true) == SeekResult{0, 1});
    CHECK(ef_list.seek(4, true) == SeekResult{1, 4});
    CHECK(ef_list.seek(20, true) == SeekResult{7, 19});
    CHECK(ef_list.seek(62, true) == SeekResult{offsets.size() - 1, 62});
    CHECK(ef_list.seek(70, true) == SeekResult{offsets.size() - 1, 62});
}

TEST_CASE("EliasFanoList32::from_encoded_data") {
    EliasFanoList32Builder expected_list{3, 3};
    expected_list.add_offset(1);
    expected_list.add_offset(2);
    expected_list.add_offset(3);
    expected_list.build();
    std::stringstream expected_list_stream;
    expected_list_stream << expected_list;
    const Bytes expected_list_bytes = string_to_bytes(expected_list_stream.str());

    CHECK(EliasFanoList32::from_encoded_data(expected_list_bytes) == expected_list.as_view());
}

}  // namespace silkworm::snapshots::elias_fano
