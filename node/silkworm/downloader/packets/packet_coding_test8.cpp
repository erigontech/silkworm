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

#include "BlockHeadersPacket.hpp"
#include "GetBlockBodiesPacket.hpp"
#include "GetBlockHeadersPacket.hpp"
#include "NewBlockHashesPacket.hpp"
#include "NewBlockPacket.hpp"
#include "RLPEth66PacketCoding.hpp"

namespace silkworm {

// TESTs related to GetBlockHeadersPacket66 encoding/decoding - eth/66 version
// ----------------------------------------------------------------------------
/*
input:
f84d88ae9405dbeebf3f01f842a0a36b1595c5acd878b63f83d3b62f6882edd27b757582f5319aebc17bc3e98246a09f20a871bf5151959fff4c88783bf4ef27b170a4cbe92b8f63ca1fe7d6ab829c
decoded:
        f84d -> list, len of len = 1 byte, len = 77
          |-- 88 -> string, 8 bytes
          |-- ae94 05db eebf 3f01 = string
          |-- f842 -> list, len of len = 1 byte, len = 66
              |-- a0 -> string, 32 bytes
                  |-- a36b1595c5acd878b63f83d3b62f6882edd27b757582f5319aebc17bc3e98246
              |-- a0 -> string, 32 bytes
                  |-- 9f20a871bf5151959fff4c88783bf4ef27b170a4cbe92b8f63ca1fe7d6ab829c
*/
TEST_CASE("GetBlockBodiesPacket (eth/66) decoding") {
    using namespace std;

    optional<Bytes> encoded = from_hex(
        "f84d88ae9405dbeebf3f01f842a0a36b1595c5acd878b63f83d3b62f6882edd27b757582f5319aebc17bc3e98246a09f20a871bf515195"
        "9fff4c88783bf4ef27b170a4cbe92b8f63ca1fe7d6ab829c");
    REQUIRE(encoded.has_value());

    GetBlockBodiesPacket66 packet;

    ByteView encoded_view = encoded.value();
    rlp::DecodingResult result = rlp::decode(encoded_view, packet);

    REQUIRE(result == rlp::DecodingResult::kOk);
    REQUIRE(packet.requestId == 0xae9405dbeebf3f01);
    REQUIRE(packet.request.size() == 2);
    REQUIRE(packet.request[0] == Hash::from_hex("a36b1595c5acd878b63f83d3b62f6882edd27b757582f5319aebc17bc3e98246"));
    REQUIRE(packet.request[1] == Hash::from_hex("9f20a871bf5151959fff4c88783bf4ef27b170a4cbe92b8f63ca1fe7d6ab829c"));
}

}  // namespace silkworm
