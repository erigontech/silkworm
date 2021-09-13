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

TEST_CASE("NewBlockHashesPacket encoding") {
    using namespace std;

    NewBlockHashesPacket packet;

    NewBlockHash newBlock;
    newBlock.hash = Hash::from_hex("eb2c33963824bf97d01cff8a65f00dc402fbf64f473cb4778a547ac08cebc354");
    newBlock.number = 12'420'112;
    packet.push_back(newBlock);

    Bytes encoded;
    rlp::encode(encoded, packet);

    REQUIRE(to_hex(encoded) == "e6e5a0eb2c33963824bf97d01cff8a65f00dc402fbf64f473cb4778a547ac08cebc35483bd8410");

    auto len = rlp::length(packet);

    REQUIRE(len == encoded.size());
}

}  // namespace silkworm
