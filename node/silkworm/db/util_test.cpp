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

#include <vector>

#include <catch2/catch.hpp>

#include "util.hpp"

namespace silkworm::db {

TEST_CASE("block key") {
    CHECK(block_key(488588).compare(ByteView({0, 0, 0, 0, 0, 7, 116, 140})) == 0);
}

TEST_CASE("encode/decode lookups") {
    uint64_t lookup{5474774};

    Bytes encoded_lookup{encode_lookup(lookup)};
    CHECK(encoded_lookup.compare(ByteView({214, 137, 83})) == 0);
    CHECK(decode_lookup(encoded_lookup) == lookup);
}

}  // namespace silkworm::db::bitmap
