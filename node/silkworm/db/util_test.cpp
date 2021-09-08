/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "util.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/endian.hpp>

namespace silkworm::db {

static const std::string hex_endian_swap(const std::string native_hex) {
    std::string ret{};
    for (unsigned int i = 0; i < native_hex.length(); i += 2) {
        ret.insert(0, native_hex.substr(i, 2));
    }
    return ret;
}

TEST_CASE("Block as key and compact form") {
    const std::string block_number_hex{"000000005485ffde"};  // i.e. 1418067934
    const std::string block_number_hex_rev{hex_endian_swap(block_number_hex)};

    auto block_number{std::stoull(block_number_hex, nullptr, 16)};
    REQUIRE(block_number == 1418067934u);

    SECTION("Block number as key") {
        // Check the sequence of bytes in memory
        ByteView block_number_view(reinterpret_cast<uint8_t*>(&block_number), sizeof(uint64_t));

#if SILKWORM_BYTE_ORDER == SILKWORM_LITTLE_ENDIAN
        // Check we've switched to native endianness
        CHECK(silkworm::to_hex(block_number_view) == block_number_hex_rev);
#else
        // Check our hex form matches input form
        CHECK(silkworm::to_hex(block_number_view) == block_number_hex);
#endif

        auto block_number_as_key{db::block_key(block_number)};
        REQUIRE(block_number_as_key.length() == sizeof(uint64_t));

        // Check data value is byte swapped if endianness requires
        auto block_number_from_key{*reinterpret_cast<uint64_t*>(block_number_as_key.data())};

#if SILKWORM_BYTE_ORDER == SILKWORM_LITTLE_ENDIAN
        CHECK(block_number_from_key != block_number);
#else
        CHECK(block_number_from_key == block_number);
#endif
        CHECK(endian::be::uint64(block_number_from_key) == block_number);
    }

    SECTION("Block number as compact") {
        // Convert block number to compact and check initial zeroes are stripped
        auto block_number_compact_bytes{to_compact(block_number)};
        CHECK(silkworm::to_hex(block_number_compact_bytes) == "5485ffde");
        // Convert back and check
        auto block_number_from_compact{from_compact(block_number_compact_bytes)};
        CHECK(block_number_from_compact == block_number);
        // Try compact empty bytes
        Bytes empty_bytes{};
        CHECK(to_compact(empty_bytes).empty() == true);
        // Try compact zeroed bytes
        Bytes zeroed_bytes(2, 0);
        CHECK(to_compact(zeroed_bytes).empty() == true);
        // Compact block == 0
        CHECK(to_compact(0).empty() == true);
        // Try retrieve a compacted value from an empty Byte string
        CHECK(from_compact(Bytes()) == 0u);
        // Try retrieve a compacted value from a too large Byte string
        Bytes extra_long_bytes(sizeof(uint64_t) + 1, 0);
        CHECK_THROWS((void)from_compact(extra_long_bytes));
    }
}

}  // namespace silkworm::db
