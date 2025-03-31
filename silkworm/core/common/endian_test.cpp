// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "endian.hpp"

#include <bit>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::endian {

TEST_CASE("16-bit Endian") {
    uint8_t bytes[2];
    uint16_t value{0x1234};

    store_big_u16(bytes, value);
    CHECK(bytes[0] == 0x12);
    CHECK(bytes[1] == 0x34);

    uint16_t be{load_big_u16(bytes)};
    CHECK(be == value);

    uint16_t le{load_little_u16(bytes)};
    CHECK(le == 0x3412);
}

TEST_CASE("32-bit Endian") {
    uint8_t bytes[4];
    uint32_t value{0x12345678};

    store_big_u32(bytes, value);
    CHECK(bytes[0] == 0x12);
    CHECK(bytes[1] == 0x34);
    CHECK(bytes[2] == 0x56);
    CHECK(bytes[3] == 0x78);

    uint32_t be{load_big_u32(bytes)};
    CHECK(be == value);

    uint32_t le{load_little_u32(bytes)};
    CHECK(le == 0x78563412);
}

TEST_CASE("64-bit Endian") {
    uint8_t bytes[8];
    uint64_t value{0x123456789abcdef0};

    store_big_u64(bytes, value);
    CHECK(bytes[0] == 0x12);
    CHECK(bytes[1] == 0x34);
    CHECK(bytes[2] == 0x56);
    CHECK(bytes[3] == 0x78);
    CHECK(bytes[4] == 0x9a);
    CHECK(bytes[5] == 0xbc);
    CHECK(bytes[6] == 0xde);
    CHECK(bytes[7] == 0xf0);

    uint64_t be{load_big_u64(bytes)};
    CHECK(be == value);

    uint64_t le{load_little_u64(bytes)};
    CHECK(le == 0xf0debc9a78563412);
}

static std::string hex_endian_swap(const std::string& native_hex) {
    std::string ret{};
    for (unsigned int i = 0; i < native_hex.length(); i += 2) {
        ret.insert(0, native_hex.substr(i, 2));
    }
    return ret;
}

TEST_CASE("Block as key and compact form") {
    const std::string block_num_hex{"000000005485ffde"};  // i.e. 1418067934
    const std::string block_num_hex_rev{hex_endian_swap(block_num_hex)};

    auto block_num{std::stoull(block_num_hex, nullptr, 16)};
    REQUIRE(block_num == 1418067934u);

    SECTION("Block number as key") {
        // Check the sequence of bytes in memory
        ByteView block_num_view(reinterpret_cast<uint8_t*>(&block_num), sizeof(uint64_t));

        if constexpr (std::endian::native == std::endian::little) {
            // Check we've switched to native endianness
            CHECK(to_hex(block_num_view) == block_num_hex_rev);
        } else {
            // Check our hex form matches input form
            CHECK(to_hex(block_num_view) == block_num_hex);
        }

        alignas(uint64_t) uint8_t block_num_as_key[8];
        store_big_u64(&block_num_as_key[0], block_num);

        // Check data value is byte swapped if endianness requires
        auto block_num_from_key{*reinterpret_cast<uint64_t*>(block_num_as_key)};

        if constexpr (std::endian::native == std::endian::little) {
            CHECK(block_num_from_key != block_num);
        } else {
            CHECK(block_num_from_key == block_num);
        }
        CHECK(intx::to_big_endian(block_num_from_key) == block_num);
    }

    SECTION("Block number as compact") {
        // Convert block number to compact and check initial zeroes are stripped
        auto block_num_compact_bytes{to_big_compact(block_num)};
        CHECK(to_hex(block_num_compact_bytes) == "5485ffde");
        // Convert back and check
        uint64_t out64{0};
        REQUIRE(from_big_compact(block_num_compact_bytes, out64));
        CHECK(out64 == block_num);
        // Try compact empty bytes
        Bytes empty_bytes{};
        CHECK(zeroless_view(empty_bytes).empty());
        // Try compact zeroed bytes
        Bytes zeroed_bytes(2, 0);
        CHECK(zeroless_view(zeroed_bytes).empty());
        // Compact block == 0
        CHECK(to_big_compact(0).empty());
        // Try retrieve a compacted value from an empty Byte string
        REQUIRE(from_big_compact(Bytes{}, out64));
        CHECK(out64 == 0u);
        // Try retrieve a compacted value from a too large Byte string
        Bytes extra_long_bytes(sizeof(uint64_t) + 1, 0);
        CHECK(from_big_compact(extra_long_bytes, out64) == tl::unexpected{DecodingError::kOverflow});

        uint32_t out32{0};
        const Bytes non_compact_be{*from_hex("00AB")};
        CHECK(from_big_compact(non_compact_be, out32) == tl::unexpected{DecodingError::kLeadingZero});
    }
}

}  // namespace silkworm::endian
