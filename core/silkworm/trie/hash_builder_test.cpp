/*
   Copyright 2020 The Silkworm Authors

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

#include "hash_builder.hpp"

#include <algorithm>
#include <catch2/catch.hpp>
#include <ethash/keccak.hpp>
#include <iterator>
#include <silkworm/common/util.hpp>

namespace silkworm::trie {

TEST_CASE("HashBuilder") {
    // The first entry
    Bytes key0{*from_hex("646f")};      // "do"
    Bytes val0{*from_hex("76657262")};  // "verb"

    // leaf node
    Bytes rlp0{*from_hex("c98320") + key0 + *from_hex("84") + val0};
    ethash::hash256 hash0{keccak256(rlp0)};

    HashBuilder hb0{key0, val0};
    CHECK(to_hex(hb0.root_hash()) == to_hex(full_view(hash0.bytes)));

    // ------------------------------------------------------------------------------------------
    // Add the second entry
    Bytes key1{*from_hex("676f6f64")};    // "good"
    Bytes val1{*from_hex("7075707079")};  // "puppy"

    // leaf node 0
    Bytes rlp1_0{*from_hex("c882206f84") + val0};
    REQUIRE(rlp1_0.length() < 32);

    // leaf node 1
    Bytes rlp1_1{*from_hex("cb84206f6f6485") + val1};
    REQUIRE(rlp1_1.length() < 32);

    // branch node
    Bytes rlp1_2{*from_hex("e68080808089") + rlp1_0 + *from_hex("80808c") + rlp1_1 + *from_hex("808080808080808080")};
    REQUIRE(rlp1_2.length() >= 32);

    ethash::hash256 hash1_2{keccak256(rlp1_2)};

    // extension node
    Bytes rlp1{*from_hex("e216a0")};
    std::copy_n(hash1_2.bytes, kHashLength, std::back_inserter(rlp1));
    ethash::hash256 hash1{keccak256(rlp1)};

    HashBuilder hb1{key0, val0};
    hb1.add(key1, val1);
    CHECK(to_hex(hb1.root_hash()) == to_hex(full_view(hash1.bytes)));
}

}  // namespace silkworm::trie
