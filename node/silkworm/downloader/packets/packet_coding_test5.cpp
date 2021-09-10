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

TEST_CASE("GetBlockHeadersPacket (eth/65) encoding") {
    using namespace std;

    GetBlockHeadersPacket packet;

    packet.origin = BlockNum{12189695};
    packet.amount = 1;
    packet.skip = 0;
    packet.reverse = false;

    Bytes encoded;
    rlp::encode(encoded, packet);

    REQUIRE(to_hex(encoded) == "c783b9ffff018080");

    auto len = rlp::length(packet);

    REQUIRE(len == encoded.size());
}

}  // namespace silkworm
