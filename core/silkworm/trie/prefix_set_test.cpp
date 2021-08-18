/*
   Copyright 2021 The Silkworm Authors

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

#include <catch2/catch.hpp>

#include <silkworm/common/cast.hpp>

namespace silkworm::trie {

TEST_CASE("Prefix set") {
    PrefixSet ps;
    CHECK(!ps.contains(string_view_to_byte_view("")));
    CHECK(!ps.contains(string_view_to_byte_view("a")));

    ps.insert(string_view_to_byte_view("abc"));
    ps.insert(string_view_to_byte_view("fg"));
    ps.insert(string_view_to_byte_view("abc"));  // duplicate
    ps.insert(string_view_to_byte_view("ab"));

    CHECK(ps.contains(string_view_to_byte_view("")));
    CHECK(ps.contains(string_view_to_byte_view("a")));
    CHECK(!ps.contains(string_view_to_byte_view("aac")));
    CHECK(ps.contains(string_view_to_byte_view("ab")));
    CHECK(ps.contains(string_view_to_byte_view("abc")));
    CHECK(!ps.contains(string_view_to_byte_view("abcd")));
    CHECK(!ps.contains(string_view_to_byte_view("b")));
    CHECK(ps.contains(string_view_to_byte_view("f")));
    CHECK(ps.contains(string_view_to_byte_view("fg")));
    CHECK(!ps.contains(string_view_to_byte_view("fgk")));
    CHECK(!ps.contains(string_view_to_byte_view("fy")));
    CHECK(!ps.contains(string_view_to_byte_view("yyz")));
}

}  // namespace silkworm::trie
