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

#include "prefix_set.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm::trie {

TEST_CASE("Prefix set - no prefix") {
    PrefixSet ps;
    REQUIRE(ps.empty());
    CHECK(!ps.contains(string_view_to_byte_view("")));
    CHECK(!ps.contains(string_view_to_byte_view("a")));

    ps.insert(string_view_to_byte_view("abc"));
    ps.insert(string_view_to_byte_view("fg"));
    ps.insert(string_view_to_byte_view("abc"));        // duplicate
    ps.insert(string_view_to_byte_view("abd"), true);  // next marked as created
    ps.insert(string_view_to_byte_view("abc"));        // duplicate
    ps.insert(string_view_to_byte_view("ab"));

    REQUIRE(ps.size() == 6);
    REQUIRE(!ps.empty());

    CHECK(ps.contains(string_view_to_byte_view("")));
    CHECK(ps.contains(string_view_to_byte_view("a")));
    CHECK(!ps.contains(string_view_to_byte_view("aac")));
    CHECK(ps.contains(string_view_to_byte_view("ab")));
    CHECK(ps.contains(string_view_to_byte_view("abc")));

    auto [contains, next_created]{ps.contains_and_next_marked(string_view_to_byte_view("abc"))};
    CHECK(contains);
    CHECK(next_created == string_view_to_byte_view("abd"));

    CHECK(!ps.contains(string_view_to_byte_view("abcd")));
    CHECK(!ps.contains(string_view_to_byte_view("b")));
    CHECK(ps.contains(string_view_to_byte_view("f")));
    CHECK(ps.contains(string_view_to_byte_view("fg")));
    CHECK(!ps.contains(string_view_to_byte_view("fgk")));
    CHECK(!ps.contains(string_view_to_byte_view("fy")));
    CHECK(!ps.contains(string_view_to_byte_view("yyz")));

    ps.clear();
    REQUIRE(ps.empty());
}

TEST_CASE("Prefix set - storage prefix") {
    Bytes prefix1{*from_hex("0x00000c28401f2ddfc4ffb8231a088e59b082343dcf32292deb61832480c3f4f50000000000000001")};
    Bytes prefix2{*from_hex("0x00000c28401f2ddfc4ffb8231a088e59b082343dcf32292deb61832480c3f4f50000000000000002")};
    PrefixSet ps;

    std::vector<std::pair<std::string, bool>> keys{};
    keys.emplace_back("ab", false);
    keys.emplace_back("abc", false);
    keys.emplace_back("abd", true);
    keys.emplace_back("abe", false);
    keys.emplace_back("abf", true);
    keys.emplace_back("fg", false);

    // Populate with first prefix
    for (const auto& item : keys) {
        Bytes prefixed{prefix1};
        prefixed.append(string_view_to_byte_view(item.first));
        ps.insert(prefixed, item.second);
    }

    // Populate with second prefix
    for (const auto& item : keys) {
        Bytes prefixed{prefix2};
        prefixed.append(string_view_to_byte_view(item.first));
        ps.insert(prefixed, item.second);
    }

    Bytes key1{prefix1};
    key1.append(string_view_to_byte_view(keys[0].first));
    {
        auto [contains, next_created]{ps.contains_and_next_marked(key1, prefix1.size())};
        REQUIRE(contains);
        REQUIRE(!next_created.empty());
        REQUIRE(std::memcmp(key1.data(), next_created.data(), 40) == 0);
    }

    key1.assign(prefix1).append(string_view_to_byte_view(keys.back().first));
    {
        auto [contains, next_created]{ps.contains_and_next_marked(key1, prefix1.size())};
        REQUIRE(contains);
        REQUIRE(next_created.empty());
    }
}

}  // namespace silkworm::trie
