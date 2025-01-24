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

#include "pattern_covering.hpp"

#include <cstdint>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

#include "patricia_tree.hpp"

namespace silkworm::snapshots::seg {

static Bytes operator""_hex(const char* data, size_t size) {
    return from_hex(std::string_view{data, size}).value();
}

TEST_CASE("PatternCoveringSearch1") {
    // hex pattern & score
    std::vector<std::pair<std::string_view, uint64_t>> patterns{
        {"0x206c6f6e676c6f6e67776f72642031", 165},
        {"0x206c6f6e676c6f6e67776f72642032", 165},
        {"0x206c6f6e676c6f6e67776f72642033", 165},
        {"0x206c6f6e676c6f6e67776f72642034", 165},
        {"0x206c6f6e676c6f6e67776f72642035", 165},
        {"0x206c6f6e676c6f6e67776f72642036", 165},
        {"0x206c6f6e676c6f6e67776f72642037", 165},
        {"0x206c6f6e676c6f6e67776f72642038", 165},
        {"0x206c6f6e676c6f6e67776f72642039", 165},
        {"0x30206c6f6e676c6f6e67776f726420", 150},
        {"0x31206c6f6e676c6f6e67776f726420", 150},
        {"0x32206c6f6e676c6f6e67776f726420", 150},
        {"0x33206c6f6e676c6f6e67776f726420", 150},
        {"0x34206c6f6e676c6f6e67776f726420", 150},
        {"0x35206c6f6e676c6f6e67776f726420", 150},
        {"0x36206c6f6e676c6f6e67776f726420", 150},
        {"0x37206c6f6e676c6f6e67776f726420", 150},
        {"0x38206c6f6e676c6f6e67776f726420", 150},
        {"0x676c6f6e67776f72642031", 121},
        {"0x676c6f6e67776f72642032", 121},
        {"0x676c6f6e67776f72642033", 121},
        {"0x676c6f6e67776f72642034", 121},
        {"0x676c6f6e67776f72642035", 121},
        {"0x676c6f6e67776f72642036", 121},
        {"0x676c6f6e67776f72642037", 121},
        {"0x676c6f6e67776f72642038", 121},
        {"0x676c6f6e67776f72642039", 121},
        {"0x67776f72642031", 77},
        {"0x67776f72642032", 77},
        {"0x67776f72642033", 77},
        {"0x67776f72642034", 77},
        {"0x67776f72642035", 77},
        {"0x67776f72642036", 77},
        {"0x67776f72642037", 77},
        {"0x67776f72642038", 77},
        {"0x67776f72642039", 77},
        {"0x6c6f6e676c6f6e67776f72642031", 154},
        {"0x6c6f6e676c6f6e67776f72642032", 154},
        {"0x6c6f6e676c6f6e67776f72642033", 154},
        {"0x6c6f6e676c6f6e67776f72642034", 154},
        {"0x6c6f6e676c6f6e67776f72642035", 154},
        {"0x6c6f6e676c6f6e67776f72642036", 154},
        {"0x6c6f6e676c6f6e67776f72642037", 154},
        {"0x6c6f6e676c6f6e67776f72642038", 154},
        {"0x6c6f6e676c6f6e67776f72642039", 154},
        {"0x6c6f6e67776f72642031", 110},
        {"0x6c6f6e67776f72642032", 110},
        {"0x6c6f6e67776f72642033", 110},
        {"0x6c6f6e67776f72642034", 110},
        {"0x6c6f6e67776f72642035", 110},
        {"0x6c6f6e67776f72642036", 110},
        {"0x6c6f6e67776f72642037", 110},
        {"0x6c6f6e67776f72642038", 110},
        {"0x6c6f6e67776f72642039", 110},
        {"0x6e676c6f6e67776f72642031", 132},
        {"0x6e676c6f6e67776f72642032", 132},
        {"0x6e676c6f6e67776f72642033", 132},
        {"0x6e676c6f6e67776f72642034", 132},
        {"0x6e676c6f6e67776f72642035", 132},
        {"0x6e676c6f6e67776f72642036", 132},
        {"0x6e676c6f6e67776f72642037", 132},
        {"0x6e676c6f6e67776f72642038", 132},
        {"0x6e676c6f6e67776f72642039", 132},
        {"0x6e67776f72642031", 88},
        {"0x6e67776f72642032", 88},
        {"0x6e67776f72642033", 88},
        {"0x6e67776f72642034", 88},
        {"0x6e67776f72642035", 88},
        {"0x6e67776f72642036", 88},
        {"0x6e67776f72642037", 88},
        {"0x6e67776f72642038", 88},
        {"0x6e67776f72642039", 88},
        {"0x6f6e676c6f6e67776f72642031", 143},
        {"0x6f6e676c6f6e67776f72642032", 143},
        {"0x6f6e676c6f6e67776f72642033", 143},
        {"0x6f6e676c6f6e67776f72642034", 143},
        {"0x6f6e676c6f6e67776f72642035", 143},
        {"0x6f6e676c6f6e67776f72642036", 143},
        {"0x6f6e676c6f6e67776f72642037", 143},
        {"0x6f6e676c6f6e67776f72642038", 143},
        {"0x6f6e676c6f6e67776f72642039", 143},
        {"0x6f6e67776f72642031", 99},
        {"0x6f6e67776f72642032", 99},
        {"0x6f6e67776f72642033", 99},
        {"0x6f6e67776f72642034", 99},
        {"0x6f6e67776f72642035", 99},
        {"0x6f6e67776f72642036", 99},
        {"0x6f6e67776f72642037", 99},
        {"0x6f6e67776f72642038", 99},
        {"0x6f6e67776f72642039", 99},
        {"0x6f72642031", 55},
        {"0x6f72642032", 55},
        {"0x6f72642033", 55},
        {"0x6f72642034", 55},
        {"0x6f72642035", 55},
        {"0x6f72642036", 55},
        {"0x6f72642037", 55},
        {"0x6f72642038", 55},
        {"0x6f72642039", 55},
        {"0x776f72642031", 66},
        {"0x776f72642032", 66},
        {"0x776f72642033", 66},
        {"0x776f72642034", 66},
        {"0x776f72642035", 66},
        {"0x776f72642036", 66},
        {"0x776f72642037", 66},
        {"0x776f72642038", 66},
        {"0x776f72642039", 66},
    };

    PatriciaTree patterns_tree;
    for (auto& pattern : patterns) {
        patterns_tree.insert(from_hex(pattern.first).value(), &pattern.second);
    }

    PatternCoveringSearch search{
        patterns_tree,
        [](void* pattern_score) { return *reinterpret_cast<uint64_t*>(pattern_score); }};

    {
        auto& result = search.cover_word("0x6c6f6e67"_hex);
        REQUIRE(result.pattern_positions.empty());
        REQUIRE(result.uncovered_ranges.size() == 1);
        CHECK(result.uncovered_ranges[0].first == 0);
        CHECK(result.uncovered_ranges[0].second == 4);
    }

    {
        auto& result = search.cover_word("0x776f7264"_hex);
        REQUIRE(result.pattern_positions.empty());
        REQUIRE(result.uncovered_ranges.size() == 1);
        CHECK(result.uncovered_ranges[0].first == 0);
        CHECK(result.uncovered_ranges[0].second == 4);
    }

    {
        auto& result = search.cover_word("0x30206c6f6e676c6f6e67776f72642030"_hex);
        REQUIRE(result.pattern_positions.size() == 1);
        CHECK(result.pattern_positions[0].first == 0);
        REQUIRE(result.uncovered_ranges.size() == 1);
        CHECK(result.uncovered_ranges[0].first == 15);
        CHECK(result.uncovered_ranges[0].second == 16);
    }

    {
        std::vector<Bytes> words = {
            "0x31206c6f6e676c6f6e67776f72642031"_hex,
            "0x32206c6f6e676c6f6e67776f72642032"_hex,
            "0x33206c6f6e676c6f6e67776f72642033"_hex,
            "0x34206c6f6e676c6f6e67776f72642034"_hex,
        };
        for (auto& word : words) {
            auto& result = search.cover_word(word);
            REQUIRE(result.pattern_positions.size() == 1);
            CHECK(result.pattern_positions[0].first == 1);
            REQUIRE(result.uncovered_ranges.size() == 1);
            CHECK(result.uncovered_ranges[0].first == 0);
            CHECK(result.uncovered_ranges[0].second == 1);
        }
    }

    {
        std::vector<Bytes> words = {
            "0x3130206c6f6e676c6f6e67776f7264203130"_hex,
            "0x3131206c6f6e676c6f6e67776f7264203131"_hex,
            "0x3230206c6f6e676c6f6e67776f7264203230"_hex,
            "0x3231206c6f6e676c6f6e67776f7264203231"_hex,
            "0x3330206c6f6e676c6f6e67776f7264203330"_hex,
            "0x3331206c6f6e676c6f6e67776f7264203331"_hex,
            "0x3938206c6f6e676c6f6e67776f7264203938"_hex,
            "0x3939206c6f6e676c6f6e67776f7264203939"_hex,
        };
        for (auto& word : words) {
            auto& result = search.cover_word(word);
            REQUIRE(result.pattern_positions.size() == 1);
            CHECK(result.pattern_positions[0].first == 2);
            REQUIRE(result.uncovered_ranges.size() == 2);
            CHECK(result.uncovered_ranges[0].first == 0);
            CHECK(result.uncovered_ranges[0].second == 2);
            CHECK(result.uncovered_ranges[1].first == 17);
            CHECK(result.uncovered_ranges[1].second == 18);
        }
    }
}

}  // namespace silkworm::snapshots::seg
