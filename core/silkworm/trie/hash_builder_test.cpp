/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "hash_builder.hpp"

#include <algorithm>
#include <iterator>

#include <catch2/catch.hpp>
#include <ethash/keccak.hpp>

#include <silkworm/common/util.hpp>
#include <silkworm/rlp/encode.hpp>

namespace silkworm::trie {

TEST_CASE("Empty trie") {
    HashBuilder hb;
    CHECK(to_hex(hb.root_hash()) == to_hex(full_view(kEmptyRoot)));
}

TEST_CASE("HashBuilder1") {
    const auto key1{0x0000000000000000000000000000000000000000000000000000000000000001_bytes32};
    const auto key2{0x0000000000000000000000000000000000000000000000000000000000000002_bytes32};

    const auto val1{*from_hex("01")};
    const auto val2{*from_hex("02")};

    HashBuilder hb;
    hb.add(full_view(key1), val1);
    hb.add(full_view(key2), val2);

    // even terminating
    const Bytes encoded_empty_terminating_path{*from_hex("20")};
    const Bytes leaf1_payload{encoded_empty_terminating_path + val1};
    const Bytes leaf2_payload{encoded_empty_terminating_path + val2};

    Bytes branch_payload;
    branch_payload.push_back(rlp::kEmptyStringCode);  // nibble 0
    branch_payload.push_back(rlp::kEmptyListCode + leaf1_payload.length());
    branch_payload.append(leaf1_payload);
    branch_payload.push_back(rlp::kEmptyListCode + leaf2_payload.length());
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
    extension_payload.push_back(rlp::kEmptyStringCode + encoded_path.length());
    extension_payload.append(encoded_path);
    extension_payload.append(branch_rlp);

    Bytes extension_rlp;
    const rlp::Header extension_head{/*list=*/true, extension_payload.length()};
    rlp::encode_header(extension_rlp, extension_head);
    extension_rlp.append(extension_payload);
    REQUIRE(extension_rlp.length() >= kHashLength);

    const ethash::hash256 hash{keccak256(extension_rlp)};
    const auto root_hash{hb.root_hash()};
    CHECK(to_hex(root_hash) == to_hex(full_view(hash.bytes)));
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
    hb0.add(key0, val0);
    CHECK(to_hex(hb0.root_hash()) == to_hex(full_view(hash0.bytes)));

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

    ethash::hash256 hash1_2{keccak256(rlp1_2)};

    // extension node
    Bytes rlp1{*from_hex("e216a0")};
    std::copy_n(hash1_2.bytes, kHashLength, std::back_inserter(rlp1));
    ethash::hash256 hash1{keccak256(rlp1)};

    HashBuilder hb1;
    hb1.add(key0, val0);
    hb1.add(key1, val1);
    CHECK(to_hex(hb1.root_hash()) == to_hex(full_view(hash1.bytes)));
}

}  // namespace silkworm::trie
