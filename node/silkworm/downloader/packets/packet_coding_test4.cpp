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

#include <catch2/catch.hpp>

#include "all_packets_with_rlp.hpp"

namespace silkworm {

// TESTs related to GetBlockHeadersPacket encoding/decoding - eth/65 version
// ----------------------------------------------------------------------------
/*
input:  c783b9ffff018080 (check!)
decoded:
         C7 = list, 7 bytes
            |-- 83b9ffff018080
                 |-- 83 = string, 3 bytes
                      |-- b9ffff
                 |-- 01 = string, value = 01
                 |-- 80 = string, 0 bytes
                 |-- 80 = string, 0 bytes
 */
TEST_CASE("GetBlockHeadersPacket (eth/65) decoding") {
    using namespace std;

    optional<Bytes> encoded = from_hex("c783b9ffff018080");
    REQUIRE(encoded.has_value());

    GetBlockHeadersPacket packet;

    ByteView encoded_view = encoded.value();
    rlp::DecodingResult result = rlp::decode(encoded_view, packet);

    REQUIRE(result == rlp::DecodingResult::kOk);
    REQUIRE(std::holds_alternative<BlockNum>(packet.origin) == true);
    REQUIRE(std::get<BlockNum>(packet.origin) == 12189695);  // intx::from_string("0xb9ffff"));
    REQUIRE(packet.amount == 1);
    REQUIRE(packet.skip == 0);
    REQUIRE(packet.reverse == false);
}

}  // namespace silkworm
