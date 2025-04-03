// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/trie/nibbles.hpp>

namespace silkworm::trie {

TEST_CASE("Nibbles") {
    std::vector<std::pair<std::string, std::string>> test_cases = {
        // Bytes -> Nibbles
        {"", ""},                                                  //
        {"00", "0000"},                                            //
        {"01", "0001"},                                            //
        {"0f", "000f"},                                            //
        {"f011", "0f000101"},                                      //
        {"f111", "0f010101"},                                      //
        {"123456789a", "0102030405060708090a"},                    //
        {"123456789f", "0102030405060708090f"},                    //
        {"12345678aa", "01020304050607080a0a"},                    //
        {"123456789abcdeff", "0102030405060708090a0b0c0d0e0f0f"},  //
    };

    for (const auto& test_case : test_cases) {
        if (test_case.first.empty()) {
            auto packed{pack_nibbles({})};
            REQUIRE(packed.empty());
            REQUIRE(unpack_nibbles(packed).empty());
            continue;
        }

        const auto packed{from_hex(test_case.first)};
        const auto unpacked{from_hex(test_case.second)};
        REQUIRE((packed.has_value() && unpacked.has_value()));
        REQUIRE(to_hex(unpack_nibbles(*packed)) == test_case.second);
        REQUIRE(to_hex(pack_nibbles(*unpacked)) == test_case.first);
    }

    // Pack an odd length nibbled key
    Bytes odd_input{1u, 2u, 3u};
    REQUIRE(to_hex(pack_nibbles(odd_input)) == "1230");
}

}  // namespace silkworm::trie
