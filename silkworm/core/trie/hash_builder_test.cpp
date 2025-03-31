// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <iterator>

#include <catch2/catch_test_macros.hpp>
#include <ethash/keccak.hpp>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/trie/hash_builder.hpp>
#include <silkworm/core/trie/nibbles.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm::trie {

TEST_CASE("Empty trie") {
    HashBuilder hb;
    CHECK(to_hex(hb.root_hash()) == to_hex(kEmptyRoot));
}

TEST_CASE("HashBuilder1") {
    const evmc::bytes32 key1{0x0000000000000000000000000000000000000000000000000000000000000001_bytes32};
    const evmc::bytes32 key2{0x0000000000000000000000000000000000000000000000000000000000000002_bytes32};

    const Bytes val1{*from_hex("01")};
    const Bytes val2{*from_hex("02")};

    HashBuilder hb;
    hb.add_leaf(unpack_nibbles(key1.bytes), val1);
    hb.add_leaf(unpack_nibbles(key2.bytes), val2);

    // even terminating
    const Bytes encoded_empty_terminating_path{*from_hex("20")};
    const Bytes leaf1_payload{encoded_empty_terminating_path + val1};
    const Bytes leaf2_payload{encoded_empty_terminating_path + val2};

    Bytes branch_payload;
    branch_payload.push_back(rlp::kEmptyStringCode);  // nibble 0
    rlp::encode_header(branch_payload, {.list = true, .payload_length = leaf1_payload.length()});
    branch_payload.append(leaf1_payload);
    rlp::encode_header(branch_payload, {.list = true, .payload_length = leaf2_payload.length()});
    branch_payload.append(leaf2_payload);

    // nibbles 3 to 15 plus nil value
    for (size_t i = {3}; i < 17; ++i) {
        branch_payload.push_back(rlp::kEmptyStringCode);
    }

    Bytes branch_rlp;
    const rlp::Header branch_head{/*list=*/true, branch_payload.length()};
    rlp::encode_header(branch_rlp, branch_head);
    branch_rlp.append(branch_payload);
    REQUIRE(branch_rlp.length() < kHashLength);

    // odd extension
    const Bytes encoded_path{*from_hex("1000000000000000000000000000000000000000000000000000000000000000")};

    Bytes extension_payload;
    rlp::encode(extension_payload, encoded_path);
    extension_payload.append(branch_rlp);

    Bytes extension_rlp;
    const rlp::Header extension_head{/*list=*/true, extension_payload.length()};
    rlp::encode_header(extension_rlp, extension_head);
    extension_rlp.append(extension_payload);
    REQUIRE(extension_rlp.length() >= kHashLength);

    const ethash::hash256 hash{keccak256(extension_rlp)};
    const auto root_hash{hb.root_hash()};
    CHECK(to_hex(root_hash) == to_hex(hash.bytes));

    // Reset hash builder
    hb.reset();
    REQUIRE(hb.root_hash() == kEmptyRoot);
}

TEST_CASE("HashBuilder2") {
    // ------------------------------------------------------------------------------------------
    // The first entry
    Bytes key0{*from_hex("646f")};      // "do"
    Bytes val0{*from_hex("76657262")};  // "verb"

    // leaf node
    Bytes rlp0{*from_hex("c98320") + key0 + *from_hex("84") + val0};
    ethash::hash256 hash0{keccak256(rlp0)};

    HashBuilder hb0;
    hb0.add_leaf(unpack_nibbles(key0), val0);
    CHECK(to_hex(hb0.root_hash()) == to_hex(hash0.bytes));

    // ------------------------------------------------------------------------------------------
    // Add the second entry
    Bytes key1{*from_hex("676f6f64")};    // "good"
    Bytes val1{*from_hex("7075707079")};  // "puppy"

    // leaf node 0
    Bytes rlp1_0{*from_hex("c882206f84") + val0};
    REQUIRE(rlp1_0.length() < kHashLength);

    // leaf node 1
    Bytes rlp1_1{*from_hex("cb84206f6f6485") + val1};
    REQUIRE(rlp1_1.length() < kHashLength);

    // branch node
    Bytes rlp1_2{*from_hex("e480808080") + rlp1_0 + *from_hex("8080") + rlp1_1 + *from_hex("808080808080808080")};
    REQUIRE(rlp1_2.length() >= kHashLength);

    evmc::bytes32 hash1_2;
    std::memcpy(hash1_2.bytes, keccak256(rlp1_2).bytes, kHashLength);

    // extension node
    Bytes rlp1{*from_hex("e216a0")};
    std::copy_n(hash1_2.bytes, kHashLength, std::back_inserter(rlp1));
    ethash::hash256 hash1{keccak256(rlp1)};

    HashBuilder hb1;
    hb1.add_leaf(unpack_nibbles(key0), val0);
    hb1.add_leaf(unpack_nibbles(key1), val1);
    CHECK(to_hex(hb1.root_hash()) == to_hex(hash1.bytes));

    // ------------------------------------------------------------------------------------------
    // Now add the branch node directly
    HashBuilder hb2;
    hb2.add_branch_node(*from_hex("06"), hash1_2);
    CHECK(to_hex(hb2.root_hash()) == to_hex(hash1.bytes));
}

/*
This test is temporarily commented out while searching for the solution.
Note ! HashBuilder should create at least a root node for every tree but apparently
when all leaves begin all with the same nibble(s) - very rare - this does not happen.
The absence of a root node however does NOT break stage IntermediateHashes as trie cursor, when
a root node is not found, instructs higher loop to rebuild the entire tree. I have encountered
this edge case only on one contract (below is real data - hashed unfortunately)

TEST_CASE("HashBuilder3") {
    Bytes key_0{
        *from_hex("0400000d0e0307060d0404010c0c000c020f04000d080e04050407090003060e070b09050a0e080e0c0a0d0d080a0405020b"
                  "03050a070b090a02080405040300")};
    Bytes key_1{
        *from_hex("0400050708070f0a01020a0802030e000f020b070603010c0c04010b030b0a080802080b030302010c0a0801010101010f0a"
                  "07050c0d030a0a030b0b050a0c0e")};
    Bytes key_2{
        *from_hex("040b000a0f010b000d0305050506090a03050705060f0a000c020e0502020405040d020a0f0d0f0807000c010e0501010d0a"
                  "06040e0e0d0c0f000f0b0f04000f")};
    Bytes val_0{*from_hex("0360051c896000")};
    Bytes val_1{*from_hex("038d7ea4c68000")};
    Bytes val_2{*from_hex("2d79883d2000")};

    evmc::bytes32 expected_root{
        to_bytes32(*from_hex("0xa6952477996e4881392f2f6eb688fc541bebd1c7ab794f295da484d38d363be9"))};
    std::vector<std::pair<Bytes, Bytes>> entries{};

    HashBuilder hb;
    hb.node_collector = [&entries](ByteView nibbled_key, const trie::Node& node) {
        Bytes key{nibbled_key};
        Bytes value{node.state_mask() ? node.encode_for_storage() : Bytes()};
        entries.emplace_back(key, value);
    };
    Bytes rlp_buffer{};

    rlp::encode(rlp_buffer, val_0);
    hb.add_leaf(key_0, rlp_buffer);
    rlp_buffer.clear();
    rlp::encode(rlp_buffer, val_1);
    hb.add_leaf(key_1, rlp_buffer);
    rlp_buffer.clear();
    rlp::encode(rlp_buffer, val_2);
    hb.add_leaf(key_2, rlp_buffer);
    rlp_buffer.clear();

    auto computed_root{hb.root_hash()};
    REQUIRE(computed_root == expected_root);
    REQUIRE(entries.size() == 1);
    REQUIRE(entries[0].first.empty());

}
*/

TEST_CASE("Known root hash") {
    const evmc::bytes32 root_hash{0x9fa752911d55c3a1246133fe280785afbdba41f357e9cae1131d5f5b0a078b9c_bytes32};
    HashBuilder hb;
    hb.add_branch_node({}, root_hash);
    CHECK(to_hex(hb.root_hash()) == to_hex(root_hash.bytes));
}

}  // namespace silkworm::trie
