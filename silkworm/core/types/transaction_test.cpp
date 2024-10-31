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

#include "silkworm/rpc/common/util.hpp"

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
        "0x04f9041701880124ec419e9796da8868b499f209983df888bb35ca86e3d9ea478"
        "82486c24309101b0e94e4ec12c49d6bcf7cc1325aa50afff92a561229fe880c716dca0e3e3d28b90"
        "2b6779e563691f1ca8a86a02efdd93db261215047dad430a475d0e191f66b580d6e759a7c7a73953"
        "2455e65160acf92dc1e1cc11970e7851277278e9d5d2549e451de8c8dd98ebdd3c55e73cd0b465875"
        "b72ea6d54917474f7ddfbd1f66d1a929694becc69bc3064c79c32b2db2a094844b400133724e046d"
        "9a96f2b6c7888fe008e6a667a970068487ce9a8e6c1260973956b26c1b78235f3452e21c5ed6d475"
        "07023ec4072b9ebea8ea9bde77ea64352ef7a6a8efb2ca61fbd0cf7c31491a4c38e3081dfc7b5e80"
        "66fca60d8f57b641032f23119a67a37ad0514529df22ba73b4028dc4a6aef0b26161371d731a81d8"
        "ac20ea90515b924f2534e32c240d0b75b5d1683e1bc7ecf8b82b73fb4c40d7cfc38e8c32f2c4d342"
        "4a86ba8c6e867f13328be201dd8d5e8ee47e03c1d9096968b71228b068cc21514f6bab7867a0d0a26"
        "51f40e927079b008c3ef11d571eb5f71d729ee9cfb3d2a99d258c10371fa1df271f4588e031498b15"
        "5244295490fd842b3055e240ea89843a188b7f15be53252367761b9a8d21818d2c756822c0383246"
        "e167dd645722aefe4ecc5e78608bcc851dc5a51255a3f91e908bb5fa53063596458f45c6e25a712de"
        "4b2a5b36eea57f5b772c84f1d0f2f2ae103445fb7f2d38493041ca452f1e846c34331bea7b5b350d02"
        "306fa3a15b50e978b4efebccce8a3479479d51c95a08e0cab0732fc4f8095337d7502c6a96219934"
        "2ed127701a6f5b0e54cbdd88f23556aab406a3a7ef49f848c3efbf4cf62052999bde1940abf494415"
        "8aefc5472f4ec9e23308cfb63deedc79e9a4f39d8b353c7e6f15d36f4c63987ae6f32701c6579e68f"
        "05f9ae86b6fbbc8d57bc17e5c2f3e5389ea75d102017767205c10d6bf5cf6e33a94ad9e6cfac5accf"
        "56d61dcee39f2e954ea89b7241e480e6021fa099a81bc9d28d6ca58a11d36f406b212be70c721bd8a"
        "4d1d643fa2bf30ebd59a4f838f794fbba2afaae8cabd778b6e151b0431e3fef0a033ce1a07081820b"
        "2a08cc2ed4355811644547f23597f7ebe516538baac51d97cbccee97f8ccf201941d994a07f0b3e92"
        "5d332d4eae10c9ba474da3d8a8806320d2ae09c60e880887dbf8422d2f6549088321947f20ebcbfef"
        "f20194327d773bdc6c27cd28a533e81074372dc33a8afd884ef63dce09c5e56c8088cb702ac89cff7"
        "65f88d26fe11c3d471949f20194f61ffc773a97207c8124c29526a59e6fa0b34a52880e563a787da9"
        "52ab808884f2a19b171abfb2882d473907f3ada086f20194c1d608bb39e078a99086e7564e89a7625"
        "ed86dca88e8a0ab45821912e88088df6c3d43080350518895a828c35680a0278088e2487fd89ca40b"
        "3488689accdbeb8d4d2e");

    Transaction decoded;
    ByteView view{encoded_rlp};
    const auto status = rlp::decode_transaction(view, decoded, rlp::Eip2718Wrapping::kBoth,
                                                rlp::Leftover::kAllow);
    REQUIRE(status);

    CHECK(decoded.type == TransactionType::kSetCode);
    CHECK(4 == std::size(decoded.authorizations));
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
        .v = intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0"),
        .r = intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0"),
        .s = intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4055"),
    });

    txn.authorizations.emplace_back(Authorization{
        .chain_id = 24,
        .address = 0x9999752c8cd697e3cb27279c330ed1ada745a8e7_address,
        .nonce = 1999,
        .v = intx::from_string<intx::uint256>("0x333241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0"),
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

}  // namespace silkworm
