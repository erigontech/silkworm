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
  Bytes key0{from_hex("646f")};
  Bytes val0{from_hex("76657262")};
  HashBuilder hb{key0, val0};
  Bytes rlp0{from_hex("c98320646f8476657262")};
  ethash::hash256 hash0{ethash::keccak256(rlp0.data(), rlp0.size())};
  CHECK(to_hex(hb.root_hash()) == to_hex(full_view(hash0.bytes)));
}
}  // namespace silkworm::trie
