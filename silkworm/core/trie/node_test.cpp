// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "node.hpp"

#include <bit>
#include <utility>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::trie {

using namespace evmc::literals;

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

    REQUIRE(std::cmp_equal(n.hashes().size(), std::popcount(n.hash_mask())));

    Bytes raw{n.encode_for_storage()};
    Node from_raw;
    REQUIRE(Node::decode_from_storage(raw, from_raw));
    CHECK(from_raw == n);

    // An empty decoding
    Node x;
    CHECK(!Node::decode_from_storage({}, x));

    // Decode from only state_mask
    raw = *from_hex("0xf607");
    CHECK(!Node::decode_from_storage(raw, x));

    // Decode with no hashes when hashmask is valued to 2
    raw = *from_hex("0xf60700054004");
    CHECK(!Node::decode_from_storage(raw, x));

    // Decode with bad hash when hashmask is valued 2
    raw = *from_hex("0xf60700054004aaaabbbb0006767767776fffffeee4444400000556764560000");
    CHECK(!Node::decode_from_storage(raw, x));

    // Decode with zero state mask (is subset fails)
    raw = *from_hex("0x000000054004");
    CHECK(!Node::decode_from_storage(raw, x));

    // Decode with more hashes than allowed
    raw = *from_hex(
        "0xf60700054004aaaabbbb0006767767776fffffeee44444000005567645600000000eeddddddd90d53cd810cc5d4243766cd4451e7b9d"
        "14b736a1148b26b3baac7617f617d321cc35c964dda53ba6c0b87798073a9628dbc9cd26b5cce88eb69655a9c609caf1cc35c964dda53b"
        "a6c0b87798073a9628dbc9cd26b5cce88eb69655a9c609caf1");
    CHECK(!Node::decode_from_storage(raw, x));
}

}  // namespace silkworm::trie
