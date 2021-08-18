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
    CHECK(!ps.contains(byte_view_of_c_str("")));
    CHECK(!ps.contains(byte_view_of_c_str("a")));

    ps.insert(byte_view_of_c_str("abc"));
    ps.insert(byte_view_of_c_str("fg"));
    ps.insert(byte_view_of_c_str("abc"));  // duplicate
    ps.insert(byte_view_of_c_str("ab"));

    CHECK(ps.contains(byte_view_of_c_str("")));
    CHECK(ps.contains(byte_view_of_c_str("a")));
    CHECK(!ps.contains(byte_view_of_c_str("aac")));
    CHECK(ps.contains(byte_view_of_c_str("ab")));
    CHECK(ps.contains(byte_view_of_c_str("abc")));
    CHECK(!ps.contains(byte_view_of_c_str("abcd")));
    CHECK(!ps.contains(byte_view_of_c_str("b")));
    CHECK(ps.contains(byte_view_of_c_str("f")));
    CHECK(ps.contains(byte_view_of_c_str("fg")));
    CHECK(!ps.contains(byte_view_of_c_str("fgk")));
    CHECK(!ps.contains(byte_view_of_c_str("fy")));
    CHECK(!ps.contains(byte_view_of_c_str("yyz")));
}

}  // namespace silkworm::trie
