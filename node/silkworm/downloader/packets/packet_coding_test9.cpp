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

TEST_CASE("GetBlockBodiesPacket (eth/66) encoding") {
    using namespace std;

    GetBlockBodiesPacket66 packet;

    packet.requestId = 0xae9405dbeebf3f01;
    packet.request.push_back(Hash::from_hex("a36b1595c5acd878b63f83d3b62f6882edd27b757582f5319aebc17bc3e98246"));
    packet.request.push_back(Hash::from_hex("9f20a871bf5151959fff4c88783bf4ef27b170a4cbe92b8f63ca1fe7d6ab829c"));

    Bytes encoded;
    rlp::encode(encoded, packet);

    REQUIRE(to_hex(encoded) ==
            "f84d88ae9405dbeebf3f01f842a0a36b1595c5acd878b63f83d3b62f6882edd27b757582f5319aebc17bc3e98246a09f20a871bf51"
            "51959fff4c88783bf4ef27b170a4cbe92b8f63ca1fe7d6ab829c");

    auto len = rlp::length(packet);

    REQUIRE(len == encoded.size());
}

}  // namespace silkworm
