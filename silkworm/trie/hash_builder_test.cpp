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

#include <catch2/catch.hpp>
#include <ethash/keccak.hpp>
#include <silkworm/common/util.hpp>

namespace silkworm::trie {

// https://eth.wiki/fundamentals/patricia-tree#example-trie
TEST_CASE("HashBuilder") {
  // The first entry
  Bytes key0{from_hex("646f")};      // "do"
  Bytes val0{from_hex("76657262")};  // "verb"

  // leaf node
  Bytes rlp0{from_hex("c98320") + key0 + from_hex("84") + val0};
  ethash::hash256 hash0{ethash::keccak256(rlp0.data(), rlp0.size())};

  HashBuilder hb{key0, val0};
  CHECK(to_hex(hb.root_hash()) == to_hex(full_view(hash0.bytes)));

  // ------------------------------------------------------------------------------------------
  // Add the second entry
  Bytes key1{key0 + from_hex("67")};   // "dog"
  Bytes val1{from_hex("7075707079")};  // "puppy"

  // leaf node
  Bytes rlp1_0{from_hex("c73785") + val1};
  REQUIRE(rlp1_0.length() < 32);

  // branch node
  Bytes rlp1_1{from_hex("dd80808080808088") + rlp1_0 + from_hex("80808080808080808084") + val0};
  REQUIRE(rlp1_1.length() < 32);

  // extension node
  Bytes rlp1{from_hex("e38300") + key0 + from_hex("9e") + rlp1_1};
  ethash::hash256 hash1{ethash::keccak256(rlp1.data(), rlp1.size())};

  hb.add(key1, val1);
  CHECK(to_hex(hb.root_hash()) == to_hex(full_view(hash1.bytes)));
}
}  // namespace silkworm::trie
