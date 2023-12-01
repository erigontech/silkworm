/*
   Copyright 2023 The Silkworm Authors

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

#include "util.hpp"

#include <catch2/catch.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm {

TEST_CASE("print Bytes", "[silkrpc][common][util]") {
    silkworm::Bytes b{};
    CHECK_NOTHROW(test_util::null_stream() << b);
}

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

TEST_CASE("byte view from string", "[silkrpc][common][util]") {
    CHECK(silkworm::byte_view_of_string("").empty());
}

TEST_CASE("bytes from string", "[silkrpc][common][util]") {
    CHECK(silkworm::bytes_of_string("").empty());
}

TEST_CASE("calculate hash of byte array", "[silkrpc][common][util]") {
    const auto eth_hash{hash_of(silkworm::ByteView{})};
    CHECK(silkworm::to_bytes32(silkworm::ByteView{eth_hash.bytes, silkworm::kHashLength}) == silkworm::kEmptyHash);
}

TEST_CASE("calculate hash of transaction", "[silkrpc][common][util]") {
    const auto eth_hash{hash_of_transaction(silkworm::Transaction{})};
    CHECK(silkworm::to_bytes32(silkworm::ByteView{eth_hash.bytes, silkworm::kHashLength}) == 0x3763e4f6e4198413383534c763f3f5dac5c5e939f0a81724e3beb96d6e2ad0d5_bytes32);
}

TEST_CASE("print ByteView", "[silkrpc][common][util]") {
    silkworm::Bytes b1;
    CHECK_NOTHROW(test_util::null_stream() << b1);
    silkworm::Bytes b2{*silkworm::from_hex("0x0608")};
    CHECK_NOTHROW(test_util::null_stream() << b2);
}

TEST_CASE("print empty address", "[silkrpc][common][util]") {
    evmc::address addr1{};
    CHECK_NOTHROW(test_util::null_stream() << addr1);
    evmc::address addr2{0xa872626373628737383927236382161739290870_address};
    CHECK_NOTHROW(test_util::null_stream() << addr2);
}

TEST_CASE("print bytes32", "[silkrpc][common][util]") {
    evmc::bytes32 b32_1{};
    CHECK_NOTHROW(test_util::null_stream() << to_hex(b32_1));
    evmc::bytes32 b32_2{0x3763e4f6e4198413383534c763f3f5dac5c5e939f0a81724e3beb96d6e2ad0d5_bytes32};
    CHECK_NOTHROW(test_util::null_stream() << to_hex(b32_2));
}

TEST_CASE("print empty const_buffer", "[silkrpc][common][util]") {
    boost::asio::const_buffer cb{};
    CHECK_NOTHROW(test_util::null_stream() << cb);
}

TEST_CASE("print empty vector of const_buffer", "[silkrpc][common][util]") {
    std::vector<boost::asio::const_buffer> v;
    boost::asio::const_buffer cb1{};
    boost::asio::const_buffer cb2{};
    v.push_back(cb1);
    v.push_back(cb2);
    CHECK_NOTHROW(test_util::null_stream() << v);
}

TEST_CASE("print Account", "[silkrpc][common][util]") {
    silkworm::Account account{};
    CHECK_NOTHROW(test_util::null_stream() << account);
}

TEST_CASE("base64 encode", "[silkrpc][common][util]") {
    uint8_t plain[] = "deadbeaf";
    auto encoded = base64_encode({plain, sizeof(plain)}, false);
    CHECK(encoded == "ZGVhZGJlYWYA");

    encoded = base64_encode({plain, sizeof(plain)}, true);
    CHECK(encoded == "ZGVhZGJlYWYA");
}

TEST_CASE("to_dec", "[silkrpc][common][util]") {
    intx::uint256 number{0x189128};
    auto encoded = to_dec(number);
    CHECK(encoded == "1610024");
}

TEST_CASE("check_tx_fee_less_cap(cap=0) returns true", "[silkrpc][common][util]") {
    intx::uint256 max_fee_per_gas{silkworm::kEther * 1};
    uint64_t gas_limit{20};
    auto check = check_tx_fee_less_cap(0, max_fee_per_gas, gas_limit);
    CHECK(check == true);
}

TEST_CASE("check_tx_fee_less_cap returns true", "[silkrpc][common][util]") {
    intx::uint256 max_fee_per_gas{silkworm::kEther * 1};
    uint64_t gas_limit{20};
    auto check = check_tx_fee_less_cap(1, max_fee_per_gas, gas_limit);
    CHECK(check == false);
}

TEST_CASE("check_tx_fee_less_cap returns false", "[silkrpc][common][util]") {
    intx::uint256 max_fee_per_gas{silkworm::kEther / 10};
    uint64_t gas_limit{8};
    auto check = check_tx_fee_less_cap(1, max_fee_per_gas, gas_limit);
    CHECK(check == true);
}

TEST_CASE("is_replay_protected(tx legacy) returns true", "[silkrpc][common][util]") {
    const Transaction txn{
        {.type = TransactionType::kAccessList,
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

    auto check = is_replay_protected(txn);
    CHECK(check == false);
}

TEST_CASE("is_replay_protected returns true", "[silkrpc][common][util]") {
    Transaction txn{
        {.type = TransactionType::kLegacy,
         .chain_id = 9,
         .nonce = 0,
         .max_priority_fee_per_gas = 20000000000,
         .max_fee_per_gas = 20000000000,
         .gas_limit = 0,
         .to = 0x0715a7794a1dc8e42615f059dd6e406a6594651a_address,
         .value = 8,
         .data = *from_hex("001122aabbcc")},
        false,                                               // odd_y_parity
        18,                                                  // r
        36,                                                  // s
        0x007fb8417eb9ad4d958b050fc3720d5b46a2c053_address,  // from
    };
    auto check = is_replay_protected(txn);
    CHECK(check == true);
}

TEST_CASE("is_replay_protected returns false", "[silkrpc][common][util]") {
    const Transaction txn{
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

    auto check = is_replay_protected(txn);
    CHECK(check == false);
}

TEST_CASE("decoding_result_to_string(kOverflow)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kOverflow) == "rlp: uint overflow");
}

TEST_CASE("decoding_result_to_string(kLeadingZero)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kLeadingZero) == "rlp: leading Zero");
}

TEST_CASE("decoding_result_to_string(kInputTooShort)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kInputTooShort) == "rlp: value size exceeds available input length");
}

TEST_CASE("decoding_result_to_string(kInputTooLong)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kInputTooLong) == "rlp: input exceeds encoded length");
}

TEST_CASE("decoding_result_to_string(kNonCanonicalSize)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kNonCanonicalSize) == "rlp: non-canonical size information");
}

TEST_CASE("decoding_result_to_string(kUnexpectedLength)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnexpectedLength) == "rlp: unexpected Length");
}

TEST_CASE("decoding_result_to_string(kUnexpectedString)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnexpectedString) == "rlp: expected list, got string instead");
}

TEST_CASE("decoding_result_to_string(kUnexpectedList)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnexpectedList) == "rlp: expected string, got list instead");
}

TEST_CASE("decoding_result_to_string(kUnexpectedListElements)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnexpectedListElements) == "rlp: unexpected list element(s)");
}

TEST_CASE("decoding_result_to_string(kInvalidVInSignature)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kInvalidVInSignature) == "rlp: invalid V in signature");
}

TEST_CASE("decoding_result_to_string(kUnsupportedTransactionType)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnsupportedTransactionType) == "rlp: unknown tx type prefix");
}

TEST_CASE("decoding_result_to_string(kInvalidFieldset)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kInvalidFieldset) == "rlp: invalid field set");
}

TEST_CASE("decoding_result_to_string(kUnexpectedEip2718Serialization)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnexpectedEip2718Serialization) == "rlp: unexpected EIP-2178 serialization");
}

TEST_CASE("decoding_result_to_string(kInvalidHashesLength)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kInvalidHashesLength) == "rlp: invalid hashes length");
}

TEST_CASE("decoding_result_to_string(kInvalidMasksSubsets)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kInvalidMasksSubsets) == "rlp: invalid masks subsets");
}

TEST_CASE("lookup_chain_config", "[silkrpc][common][util]") {
    SECTION("lookup known chain") {
        for (const auto& [_, known_chain_id] : kKnownChainNameToId) {
            CHECK_NOTHROW(lookup_chain_config(known_chain_id) != nullptr);
        }
    }
    SECTION("lookup unknown chain") {
        CHECK_THROWS_AS(lookup_chain_config(0), std::runtime_error);
    }
}

}  // namespace silkworm
