/*
   Copyright 2022 The Silkworm Authors

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

#include <bit>

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>

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

    REQUIRE(n.hashes().size() == static_cast<size_t>(std::popcount(n.hash_mask())));

    Bytes raw{n.encode_for_storage()};
    std::optional<Node> from_raw{Node::decode_from_storage(raw)};
    REQUIRE(from_raw.has_value());
    REQUIRE(*from_raw == n);

    REQUIRE(to_hex(from_raw->state_mask()) == "f607");
    REQUIRE(to_hex(from_raw->tree_mask()) == "05");
    REQUIRE(to_hex(from_raw->hash_mask()) == "4004");
    REQUIRE(from_raw->root_hash().has_value());
    REQUIRE(from_raw->hashes().size() == 2);

    // An empty decoding
    REQUIRE(Node::decode_from_storage({}).has_value() == false);

    // Decode from only state_mask
    raw = *from_hex("0xf607");
    REQUIRE(Node::decode_from_storage(raw).has_value() == false);

    // Decode with no hashes when hashmask is valued to 2
    raw = *from_hex("0xf60700054004");
    REQUIRE(Node::decode_from_storage(raw).has_value() == false);

    // Decode with bad hash when hashmask is valued 2
    raw = *from_hex("0xf60700054004aaaabbbb0006767767776fffffeee4444400000556764560000");
    REQUIRE(Node::decode_from_storage(raw).has_value() == false);

    // Decode with zero state mask (is subset fails)
    raw = *from_hex("0x000000054004");
    REQUIRE(Node::decode_from_storage(raw).has_value() == false);

    // Decode with more hashes than allowed
    raw = *from_hex(
        "0xf60700054004aaaabbbb0006767767776fffffeee44444000005567645600000000eeddddddd90d53cd810cc5d4243766cd4451e7b9d"
        "14b736a1148b26b3baac7617f617d321cc35c964dda53ba6c0b87798073a9628dbc9cd26b5cce88eb69655a9c609caf1cc35c964dda53b"
        "a6c0b87798073a9628dbc9cd26b5cce88eb69655a9c609caf1");
    REQUIRE(Node::decode_from_storage(raw).has_value() == false);
}

}  // namespace silkworm::trie
