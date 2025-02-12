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

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm {

using namespace evmc::literals;

static const std::vector<AccessListEntry> kAccessList{
    {0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae_address,
     {
         0x0000000000000000000000000000000000000000000000000000000000000003_bytes32,
         0x0000000000000000000000000000000000000000000000000000000000000007_bytes32,
     }},
    {0xbb9bc244d798123fde783fcc1c72d3bb8c189413_address, {}},
};

TEST_CASE("Legacy Transaction RLP") {
    Transaction txn{};
    txn.type = TransactionType::kLegacy;
    txn.chain_id = 1;
    txn.nonce = 12;
    txn.max_priority_fee_per_gas = 20000000000;
    txn.max_fee_per_gas = 20000000000;
    txn.gas_limit = 21000;
    txn.to = 0x727fc6a68321b754475c668a6abfb6e9e71c169a_address;
    txn.value = 10 * kEther;
    txn.data = *from_hex(
        "a9059cbb000000000213ed0f886efd100b67c7e4ec0a85a7d20dc9716000000000000000000"
        "00015af1d78b58c4000");
    txn.odd_y_parity = true;
    txn.r = intx::from_string<intx::uint256>("0xbe67e0a07db67da8d446f76add590e54b6e92cb6b8f9835aeb67540579a27717");
    txn.s = intx::from_string<intx::uint256>("0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7bd718");

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
    decoded.access_list = kAccessList;
    decoded.max_fee_per_blob_gas = 123;
    decoded.blob_versioned_hashes.emplace_back(0xefc552d1df2a6a8e2643912171d040e4de0db43cd53b728c3e4d26952f710be8_bytes32);
    decoded.set_sender(0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address);
    view = encoded;
    REQUIRE(rlp::decode(view, decoded));
    CHECK(view.empty());
    CHECK(decoded == txn);
    CHECK_FALSE(decoded.sender());
}

TEST_CASE("EIP-2930 Transaction RLP") {
    Transaction txn{};
    txn.type = TransactionType::kAccessList;
    txn.chain_id = kSepoliaConfig.chain_id;
    txn.nonce = 7;
    txn.max_priority_fee_per_gas = 30000000000;
    txn.max_fee_per_gas = 30000000000;
    txn.gas_limit = 5748100;
    txn.to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address;
    txn.value = 2 * kEther;
    txn.data = *from_hex("6ebaf477f83e051589c1188bcc6ddccd");
    txn.access_list = kAccessList;
    txn.odd_y_parity = false;
    txn.r = intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0");
    txn.s = intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094");

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
    decoded.set_sender(0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address);
    view = encoded_wrapped;
    REQUIRE(rlp::decode(view, decoded));
    CHECK(decoded == txn);
    CHECK(!decoded.sender());
}

TEST_CASE("EIP-1559 Transaction RLP") {
    Transaction txn{};
    txn.type = TransactionType::kDynamicFee;
    txn.chain_id = kSepoliaConfig.chain_id;
    txn.nonce = 7;
    txn.max_priority_fee_per_gas = 10000000000;
    txn.max_fee_per_gas = 30000000000;
    txn.gas_limit = 5748100;
    txn.to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address;
    txn.value = 2 * kEther;
    txn.data = *from_hex("6ebaf477f83e051589c1188bcc6ddccd");
    txn.access_list = kAccessList;
    txn.odd_y_parity = false;
    txn.r = intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0");
    txn.s = intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094");

    Bytes encoded{};
    rlp::encode(encoded, txn);

    Transaction decoded;
    ByteView view{encoded};
    REQUIRE(rlp::decode(view, decoded));
    CHECK(view.empty());
    CHECK(decoded == txn);
}

TEST_CASE("EIP-4844 Transaction RLP") {
    Transaction txn{};
    txn.type = TransactionType::kBlob;
    txn.chain_id = kSepoliaConfig.chain_id;
    txn.nonce = 7;
    txn.max_priority_fee_per_gas = 10000000000;
    txn.max_fee_per_gas = 30000000000;
    txn.gas_limit = 5748100;
    txn.to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address;
    txn.data = *from_hex("04f7");
    txn.access_list = kAccessList;
    txn.max_fee_per_blob_gas = 123;
    txn.blob_versioned_hashes = {
        0xc6bdd1de713471bd6cfa62dd8b5a5b42969ed09e26212d3377f3f8426d8ec210_bytes32,
        0x8aaeccaf3873d07cef005aca28c39f8a9f8bdb1ec8d79ffc25afc0a4fa2ab736_bytes32,
    };
    txn.odd_y_parity = true;
    txn.r = intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0");
    txn.s = intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094");

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
    Transaction txn{};
    txn.type = TransactionType::kLegacy;
    txn.nonce = 0;
    txn.max_priority_fee_per_gas = 50'000 * kGiga;
    txn.max_fee_per_gas = 50'000 * kGiga;
    txn.gas_limit = 21'000;
    txn.to = 0x5df9b87991262f6ba471f09758cde1c0fc1de734_address;
    txn.value = 31337;
    txn.odd_y_parity = true;
    txn.r = intx::from_string<intx::uint256>("0x88ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0");
    txn.s = intx::from_string<intx::uint256>("0x45e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a");

    CHECK(txn.sender() == 0xa1e4380a3b1f749673e270229993ee55f35663b4_address);
    CHECK(txn.hash() == 0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060_bytes32);
}

TEST_CASE("Recover sender 2") {
    // https://etherscan.io/tx/0xe17d4d0c4596ea7d5166ad5da600a6fdc49e26e0680135a2f7300eedfd0d8314
    // Block 46214
    Transaction txn{};
    txn.type = TransactionType::kLegacy;
    txn.nonce = 1;
    txn.max_priority_fee_per_gas = 50'000 * kGiga;
    txn.max_fee_per_gas = 50'000 * kGiga;
    txn.gas_limit = 21'750;
    txn.to = 0xc9d4035f4a9226d50f79b73aafb5d874a1b6537e_address;
    txn.value = 31337;
    txn.data = *from_hex("0x74796d3474406469676978");
    txn.odd_y_parity = true;
    txn.r = intx::from_string<intx::uint256>("0x1c48defe76d367bb92b4fc0628aca42a4d8037062865635d955673e57eddfbfa");
    txn.s = intx::from_string<intx::uint256>("0x65f766849f97b15f01d0877636fbed0fa4e39f8834896c0354f56ac44dcb50a6");

    CHECK(txn.sender() == 0xa1e4380a3b1f749673e270229993ee55f35663b4_address);
    CHECK(txn.hash() == 0xe17d4d0c4596ea7d5166ad5da600a6fdc49e26e0680135a2f7300eedfd0d8314_bytes32);
}

TEST_CASE("SetCodeTx parsing with authorizations") {
    const auto encoded_rlp = *from_hex(
        "b8ba04f8b70101843b9aca00847735940082520894deadbeefdeadbeefdeadbeefdeadbeefdeadbeef880de0b6b3a76400008a64756d6d7920636f6465c0f879db0194000000000000000000000000000000000000000101806f81dede01940000000000000000000000000000000000000002020182014d8201bcde01940000000000000000000000000000000000000003038082022b82029ade019400000000000000000000000000000000000000040401820309820378808080");

    Transaction decoded;
    ByteView view{encoded_rlp};
    const auto status = rlp::decode_transaction(view, decoded, rlp::Eip2718Wrapping::kBoth,
                                                rlp::Leftover::kProhibit);
    REQUIRE(status);

    CHECK(decoded.type == TransactionType::kSetCode);
    CHECK(4 == std::size(decoded.authorizations));

    CHECK(decoded.authorizations[0].address == 0x0000000000000000000000000000000000000001_address);
    CHECK(decoded.authorizations[0].nonce == 1);
    CHECK(decoded.authorizations[0].y_parity == 0);

    CHECK(decoded.authorizations[1].address == 0x0000000000000000000000000000000000000002_address);
    CHECK(decoded.authorizations[1].nonce == 2);
    CHECK(decoded.authorizations[1].y_parity == 1);

    CHECK(decoded.authorizations[2].address == 0x0000000000000000000000000000000000000003_address);
    CHECK(decoded.authorizations[2].nonce == 3);
    CHECK(decoded.authorizations[2].y_parity == 0);

    CHECK(decoded.authorizations[3].address == 0x0000000000000000000000000000000000000004_address);
    CHECK(decoded.authorizations[3].nonce == 4);
    CHECK(decoded.authorizations[3].y_parity == 1);
}

TEST_CASE("SetCodeTx encoding and decoding") {
    Transaction txn{};
    txn.type = TransactionType::kSetCode;
    txn.chain_id = kSepoliaConfig.chain_id;
    txn.nonce = 7;
    txn.max_priority_fee_per_gas = 30000000000;
    txn.max_fee_per_gas = 30000000000;
    txn.gas_limit = 5748100;
    txn.to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address;
    txn.value = 2 * kEther;
    txn.data = *from_hex("6ebaf477f83e051589c1188bcc6ddccd");
    txn.odd_y_parity = false;
    txn.r = intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0");
    txn.s = intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094");

    txn.authorizations.emplace_back(Authorization{
        .chain_id = 4,
        .address = 0x811a752c8cd697e3cb27279c330ed1ada745a8e7_address,
        .nonce = 10,
        .y_parity = 26,
        .r = intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0"),
        .s = intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4055"),
    });

    txn.authorizations.emplace_back(Authorization{
        .chain_id = 24,
        .address = 0x9999752c8cd697e3cb27279c330ed1ada745a8e7_address,
        .nonce = 1999,
        .y_parity = 22,
        .r = intx::from_string<intx::uint256>("0x444241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0"),
        .s = intx::from_string<intx::uint256>("0x555cc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4055"),
    });

    Bytes encoded{};
    rlp::encode(encoded, txn);

    Transaction decoded;
    ByteView view{encoded};
    auto status = rlp::decode_transaction(view, decoded, rlp::Eip2718Wrapping::kBoth, rlp::Leftover::kProhibit);
    REQUIRE(status);
    CHECK(view.empty());
    CHECK(decoded == txn);
}

TEST_CASE("SetCodeTx authorization recover signer") {
    Authorization authorization{
        .chain_id = 7088110746,
        .address = 0xb47d9c634d50f1600d4df767e9474c25a0303428_address,
        .nonce = 1,
        .y_parity = 1,
        .r = intx::uint256(uint64_t{11238962557009670571U}, uint64_t{14017651393191758745U}, uint64_t{18358999445216475025U}, uint64_t{5549385460848219779U}),
        .s = intx::uint256(uint64_t{6390522493159340108U}, uint64_t{17630603794136184458U}, uint64_t{14442462445950880280U}, uint64_t{846710983706847255U})};

    authorization.recover_authority();
    CHECK(authorization.recovered_authority.value() == 0x8ED5ABe9DE62dB2F266b06b86203f71e4C1e357f_address);
}

}  // namespace silkworm
