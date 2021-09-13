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

// TESTs related to BlockHeadersPacket66 encoding/decoding - eth/66 version
// ----------------------------------------------------------------------------
/*
input:
f902268881fb063b42d7d3a1f9021af90217a01173372d36e7b89b1075c7b2bb95b3188152ebc280cdcea2a30d9c2f160d7ad9a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347941ad91ee08f21be3de0ba2ba6918e714da6b45836a004e5bba69de173c51b99971d8ac196baa3e56ef66547e883bd30c806a78fba57a04bab19e8b732de1dbffa13abc7434e1c6542582189ab070b866f5d4d20120835a08799aa15763141e3250da3ff6bf39b396d607410a775f59270567b3b781e341fb9010004625d8f41626080128265fd940c9ae229b1a2a0ba05022001d921e15418db20984f10777083728dd201d92f270d05d6425d2d5808273214227bcfa172e624a90a6d150c20198029c842420b0638c4e015464a24034c5c4c1052d8d4dec00b7154c4010d0af16804130093c05103d868380082f0c8bc0ce52682879a20884562da88c7020b21212599ffd0582192ce0d50985c814554e29a741003c82039c1b0ebd1860111aae631f5cd4694aa104ee51f0701c9b0064430e020beab7819070011de5d52aa0504c023273036a13e01444847128414ed6014283038e683e9625c7690a4819a0b0206e328d4d5923c2182800dc952c8cf06c4606b8f1208932877871b62dd9dc8f70583c0279d83e3c41f83e39def8460bf38e696486976656f6e2065752d68656176792d322054556953a0dc1adc2afa14307c6860ad218335c34378d1dea92124717d638e86b59f5666d2889fcb87e658cd635f
decoded:
         f9 0226 -> list (list-len = 2 bytes), len = 550
              |-- 88 -> string, 8 bytes
                 |-- 81fb 063b 42d7 d3a1 -> string
              |-- f9 021a -> list (list-len = 2 bytes), len = 538
                 |-- ...

*/
TEST_CASE("BlockHeadersPacket (eth/66) decoding/encoding") {
    using namespace std;
    using intx::operator""_u256;

    // packet captured from network (with wireshark)
    string raw_packet =
        "f902268881fb063b42d7d3a1f9021af90217a01173372d36e7b89b1075c7b2bb95b3188152ebc280cdcea2a30d9c2f160d7ad9a01dcc4d"
        "e8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347941ad91ee08f21be3de0ba2ba6918e714da6b45836a004e5bba6"
        "9de173c51b99971d8ac196baa3e56ef66547e883bd30c806a78fba57a04bab19e8b732de1dbffa13abc7434e1c6542582189ab070b866f"
        "5d4d20120835a08799aa15763141e3250da3ff6bf39b396d607410a775f59270567b3b781e341fb9010004625d8f41626080128265fd94"
        "0c9ae229b1a2a0ba05022001d921e15418db20984f10777083728dd201d92f270d05d6425d2d5808273214227bcfa172e624a90a6d150c"
        "20198029c842420b0638c4e015464a24034c5c4c1052d8d4dec00b7154c4010d0af16804130093c05103d868380082f0c8bc0ce5268287"
        "9a20884562da88c7020b21212599ffd0582192ce0d50985c814554e29a741003c82039c1b0ebd1860111aae631f5cd4694aa104ee51f07"
        "01c9b0064430e020beab7819070011de5d52aa0504c023273036a13e01444847128414ed6014283038e683e9625c7690a4819a0b0206e3"
        "28d4d5923c2182800dc952c8cf06c4606b8f1208932877871b62dd9dc8f70583c0279d83e3c41f83e39def8460bf38e696486976656f6e"
        "2065752d68656176792d322054556953a0dc1adc2afa14307c6860ad218335c34378d1dea92124717d638e86b59f5666d2889fcb87e658"
        "cd635f";
    optional<Bytes> encoded = from_hex(raw_packet);
    REQUIRE(encoded.has_value());

    // decoding
    BlockHeadersPacket66 packet;
    ByteView encoded_view = encoded.value();
    rlp::DecodingResult result = rlp::decode(encoded_view, packet);

    // packet values from etherscan
    REQUIRE(result == rlp::DecodingResult::kOk);
    REQUIRE(packet.requestId == 0x81fb'063b'42d7'd3a1);
    REQUIRE(packet.request.size() == 1);
    REQUIRE(packet.request[0].number == 12593053);
    REQUIRE(packet.request[0].gas_limit == 14'926'879);
    REQUIRE(packet.request[0].gas_used == 14'917'103);
    REQUIRE(packet.request[0].difficulty == 7708528345675525_u256);

    // encoding test
    Bytes re_encoded;
    rlp::encode(re_encoded, packet);
    REQUIRE(to_hex(re_encoded) == raw_packet);  // REQUIRE(encoded == re_encoded);

    // length test
    auto len = rlp::length(packet);
    REQUIRE(len == re_encoded.size());
}

// TESTs related to BlockBodiesPacket66 encoding/decoding - eth/66 version
// ----------------------------------------------------------------------------
/*
input:  ...
decoded:
*/

TEST_CASE("BlockBodiesPacket (eth/66) decoding/encoding") {
    // todo: implement!
}

}  // namespace silkworm
