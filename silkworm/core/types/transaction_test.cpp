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

#include "transaction.hpp"

#include <catch2/catch.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm {

const std::vector<AccessListEntry> access_list{
    {0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae_address,
     {
         0x0000000000000000000000000000000000000000000000000000000000000003_bytes32,
         0x0000000000000000000000000000000000000000000000000000000000000007_bytes32,
     }},
    {0xbb9bc244d798123fde783fcc1c72d3bb8c189413_address, {}},
};

TEST_CASE("Legacy Transaction RLP") {
    Transaction txn{
        {.type = TransactionType::kLegacy,
         .chain_id = 1,
         .nonce = 12,
         .max_priority_fee_per_gas = 20000000000,
         .max_fee_per_gas = 20000000000,
         .gas_limit = 21000,
         .to = 0x727fc6a68321b754475c668a6abfb6e9e71c169a_address,
         .value = 10 * kEther,
         .data = *from_hex("a9059cbb000000000213ed0f886efd100b67c7e4ec0a85a7d20dc9716000000000000000000"
                           "00015af1d78b58c4000")},
        true,                                                                                                    // odd_y_parity
        intx::from_string<intx::uint256>("0xbe67e0a07db67da8d446f76add590e54b6e92cb6b8f9835aeb67540579a27717"),  // r
        intx::from_string<intx::uint256>("0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7bd718"),  // s
    };

    Bytes encoded{};
    rlp::encode(encoded, txn);

    Transaction decoded;
    ByteView view{encoded};
    REQUIRE(rlp::decode(view, decoded));
    CHECK(view.empty());
    CHECK(decoded == txn);

    // Check that non-legacy fields (access_list, max_fee_per_blob_gas, blob_versioned_hashes) and from are cleared
    decoded.max_priority_fee_per_gas = 17;
    decoded.max_fee_per_gas = 31;
    decoded.access_list = access_list;
    decoded.max_fee_per_blob_gas = 123;
    decoded.blob_versioned_hashes.emplace_back(0xefc552d1df2a6a8e2643912171d040e4de0db43cd53b728c3e4d26952f710be8_bytes32);
    decoded.from = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address;
    view = encoded;
    REQUIRE(rlp::decode(view, decoded));
    CHECK(view.empty());
    CHECK(decoded == txn);
    CHECK_FALSE(decoded.from.has_value());
}

TEST_CASE("EIP-2930 Transaction RLP") {
    Transaction txn{
        {.type = TransactionType::kAccessList,
         .chain_id = 5,
         .nonce = 7,
         .max_priority_fee_per_gas = 30000000000,
         .max_fee_per_gas = 30000000000,
         .gas_limit = 5748100,
         .to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address,
         .value = 2 * kEther,
         .data = *from_hex("6ebaf477f83e051589c1188bcc6ddccd"),
         .access_list = access_list},
        false,                                                                                                   // odd_y_parity
        intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0"),  // r
        intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094"),  // s
    };

    // Raw serialization
    Bytes encoded_raw;
    rlp::encode(encoded_raw, txn, /*wrap_eip2718_into_string=*/false);

    Transaction decoded;
    ByteView view{encoded_raw};
    REQUIRE(rlp::decode_transaction(view, decoded, rlp::Eip2718Wrapping::kNone));
    CHECK(view.empty());
    CHECK(decoded == txn);

    view = encoded_raw;
    CHECK(rlp::decode_transaction(view, decoded, rlp::Eip2718Wrapping::kString) ==
          tl::unexpected{DecodingError::kUnexpectedEip2718Serialization});

    view = encoded_raw;
    REQUIRE(rlp::decode_transaction(view, decoded, rlp::Eip2718Wrapping::kBoth));
    CHECK(view.empty());
    CHECK(decoded == txn);

    // Wrap into an RLP string
    Bytes encoded_wrapped;
    rlp::encode(encoded_wrapped, txn, /*wrap_eip2718_into_string=*/true);

    view = encoded_wrapped;
    CHECK(rlp::decode_transaction(view, decoded, rlp::Eip2718Wrapping::kNone) ==
          tl::unexpected{DecodingError::kUnexpectedEip2718Serialization});

    view = encoded_wrapped;
    REQUIRE(rlp::decode_transaction(view, decoded, rlp::Eip2718Wrapping::kString));
    CHECK(view.empty());
    CHECK(decoded == txn);

    view = encoded_wrapped;
    REQUIRE(rlp::decode_transaction(view, decoded, rlp::Eip2718Wrapping::kBoth));
    CHECK(view.empty());
    CHECK(decoded == txn);

    // Check that post-EIP-2930 fields (max_fee_per_blob_gas, blob_versioned_hashes) and from are cleared
    decoded.max_priority_fee_per_gas = 17;
    decoded.max_fee_per_gas = 31;
    decoded.max_fee_per_blob_gas = 123;
    decoded.blob_versioned_hashes.emplace_back(0xefc552d1df2a6a8e2643912171d040e4de0db43cd53b728c3e4d26952f710be8_bytes32);
    decoded.from = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address;
    view = encoded_wrapped;
    REQUIRE(rlp::decode(view, decoded));
    CHECK(decoded == txn);
    CHECK(!decoded.from);
}

TEST_CASE("EIP-1559 Transaction RLP") {
    Transaction txn{
        {.type = TransactionType::kDynamicFee,
         .chain_id = 5,
         .nonce = 7,
         .max_priority_fee_per_gas = 10000000000,
         .max_fee_per_gas = 30000000000,
         .gas_limit = 5748100,
         .to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address,
         .value = 2 * kEther,
         .data = *from_hex("6ebaf477f83e051589c1188bcc6ddccd"),
         .access_list = access_list},
        false,                                                                                                   // odd_y_parity
        intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0"),  // r
        intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094"),  // s
    };

    Bytes encoded{};
    rlp::encode(encoded, txn);

    Transaction decoded;
    ByteView view{encoded};
    REQUIRE(rlp::decode(view, decoded));
    CHECK(view.empty());
    CHECK(decoded == txn);
}

TEST_CASE("EIP-4844 Transaction RLP") {
    Transaction txn{
        {.type = TransactionType::kBlob,
         .chain_id = 5,
         .nonce = 7,
         .max_priority_fee_per_gas = 10000000000,
         .max_fee_per_gas = 30000000000,
         .gas_limit = 5748100,
         .to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address,
         .data = *from_hex("04f7"),
         .access_list = access_list,
         .max_fee_per_blob_gas = 123,
         .blob_versioned_hashes = {
             0xc6bdd1de713471bd6cfa62dd8b5a5b42969ed09e26212d3377f3f8426d8ec210_bytes32,
             0x8aaeccaf3873d07cef005aca28c39f8a9f8bdb1ec8d79ffc25afc0a4fa2ab736_bytes32,
         }},
        true,                                                                                                    // odd_y_parity
        intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0"),  // r
        intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094"),  // s
    };

    Bytes encoded{};
    rlp::encode(encoded, txn);

    Transaction decoded;
    ByteView view{encoded};
    REQUIRE(rlp::decode(view, decoded));
    CHECK(view.empty());
    CHECK(decoded == txn);
}

TEST_CASE("Recover sender 1") {
    // https://etherscan.io/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060
    // Block 46147
    Transaction txn{
        {.type = TransactionType::kLegacy,
         .nonce = 0,
         .max_priority_fee_per_gas = 50'000 * kGiga,
         .max_fee_per_gas = 50'000 * kGiga,
         .gas_limit = 21'000,
         .to = 0x5df9b87991262f6ba471f09758cde1c0fc1de734_address,
         .value = 31337},
        true,                                                                                                    // odd_y_parity
        intx::from_string<intx::uint256>("0x88ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0"),  // r
        intx::from_string<intx::uint256>("0x45e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a"),  // s
    };

    txn.recover_sender();
    CHECK(txn.from == 0xa1e4380a3b1f749673e270229993ee55f35663b4_address);
    txn.recover_sender();  // Only for coverage - should not recover twice
    CHECK(txn.hash() == 0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060_bytes32);
}

TEST_CASE("Recover sender 2") {
    // https://etherscan.io/tx/0xe17d4d0c4596ea7d5166ad5da600a6fdc49e26e0680135a2f7300eedfd0d8314
    // Block 46214
    Transaction txn{
        {.type = TransactionType::kLegacy,
         .nonce = 1,
         .max_priority_fee_per_gas = 50'000 * kGiga,
         .max_fee_per_gas = 50'000 * kGiga,
         .gas_limit = 21'750,
         .to = 0xc9d4035f4a9226d50f79b73aafb5d874a1b6537e_address,
         .value = 31337,
         .data = *from_hex("0x74796d3474406469676978")},
        true,                                                                                                    // odd_y_parity
        intx::from_string<intx::uint256>("0x1c48defe76d367bb92b4fc0628aca42a4d8037062865635d955673e57eddfbfa"),  // r
        intx::from_string<intx::uint256>("0x65f766849f97b15f01d0877636fbed0fa4e39f8834896c0354f56ac44dcb50a6"),  // s
    };

    txn.recover_sender();
    CHECK(txn.from == 0xa1e4380a3b1f749673e270229993ee55f35663b4_address);
    CHECK(txn.hash() == 0xe17d4d0c4596ea7d5166ad5da600a6fdc49e26e0680135a2f7300eedfd0d8314_bytes32);
}

}  // namespace silkworm
