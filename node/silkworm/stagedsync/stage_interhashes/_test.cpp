/*
   Copyright 2021-2022 The Silkworm Authors

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

#include <catch2/catch.hpp>

#include <silkworm/stagedsync/stage_interhashes/trie_cursor.hpp>

namespace silkworm::trie {

static Bytes nibbles_from_hex(std::string_view source) {
    Bytes unpacked(source.size(), '\0');
    for (size_t i{0}; i < source.size(); ++i) {
        unpacked[i] = *decode_hex_digit(source[i]);
    }
    return unpacked;
}

static std::string nibbles_to_hex(ByteView unpacked) {
    static const char* kHexDigits{"0123456789ABCDEF"};
    std::string out;
    out.reserve(unpacked.length());
    for (uint8_t x : unpacked) {
        out.push_back(kHexDigits[x]);
    }
    return out;
}

TEST_CASE("increment_key") {
    // Pairs of sources and expected value after increment
    std::vector<std::pair<std::string, std::string>> tests{
        {"12", "13"},      //
        {"12FE", "12FF"},  //
        {"1F", "2"},       //
        {"F", "null"},     //
        {"FF", "null"},    //
        {"FFF", "null"},   //
        {"FFFE", "FFFF"},  //
        {"120", "121"},    //
        {"12E", "12F"},    //
        {"12F", "13"},     //
        {"1FF", "2"},      //
    };

    for (auto& [source, expected] : tests) {
        auto unpacked{nibbles_from_hex(source)};
        auto unpacked_incremented{increment_key(unpacked)};
        if (expected == "null") {
            REQUIRE(unpacked_incremented.has_value() == false);
        } else {
            REQUIRE(expected == nibbles_to_hex(*unpacked_incremented));
        }
    }
}

}  // namespace silkworm::trie
