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

// TESTs related to GetBlockHeadersPacket66 encoding/decoding - eth/66 version
// ----------------------------------------------------------------------------
/*
input:  d1886b1a456ba6e2f81dc783b9ffff018080
decoded:
        d1 = list, 17 bytes
         |-- 886b1a456ba6e2f81dc783b9ffff018080
               |-- 88 = string, 8 bytes
                    |-- 6b1a456ba6e2f81d
               |-- C7 = list, 7 bytes
                    |-- 83b9ffff018080
                          |-- 83 = string, 3 bytes
                               |-- b9ffff
                          |-- 01 = string, value = 01
                          |-- 80 = string, 0 bytes
                          |-- 80 = string, 0 bytes
 */
TEST_CASE("GetBlockHeadersPacket (eth/66) decoding") {
    using namespace std;

    optional<Bytes> encoded = from_hex("d1886b1a456ba6e2f81dc783b9ffff018080");
    REQUIRE(encoded.has_value());

    GetBlockHeadersPacket66 packet;

    ByteView encoded_view = encoded.value();
    rlp::DecodingResult result = rlp::decode(encoded_view, packet);

    REQUIRE(result == rlp::DecodingResult::kOk);
    REQUIRE(packet.requestId == 0x6b1a456ba6e2f81d);
    REQUIRE(std::holds_alternative<BlockNum>(packet.request.origin) == true);
    REQUIRE(std::get<BlockNum>(packet.request.origin) == 0xb9ffff);  // 12189695
    REQUIRE(packet.request.amount == 1);
    REQUIRE(packet.request.skip == 0);
    REQUIRE(packet.request.reverse == false);
}

}  // namespace silkworm
