/*
   Copyright 2021 The Silkworm Authors

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

#include "node.hpp"

#include <bitset>

#include <catch2/catch.hpp>

namespace silkworm::trie {

TEST_CASE("Node marshalling") {
    Node n{/*state_mask*/ 0xf607,
           /*tree_mask*/ 0x0005,
           /*hash_mask*/ 0x4004,
           /*hashes*/
           {
               0x90d53cd810cc5d4243766cd4451e7b9d14b736a1148b26b3baac7617f617d321_bytes32,
               0xcc35c964dda53ba6c0b87798073a9628dbc9cd26b5cce88eb69655a9c609caf1_bytes32,
           },
           /*root_hash*/ 0xaaaabbbb0006767767776fffffeee44444000005567645600000000eeddddddd_bytes32};

    REQUIRE(std::bitset<16>(n.hash_mask()).count() == n.hashes().size());

    Bytes b{marshal_node(n)};

    CHECK(unmarshal_node(b) == n);
}

}  // namespace silkworm::trie
