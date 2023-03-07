/*
   Copyright 2021 The Silkrpc Authors

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
#include <silkworm/core/common/util.hpp>

#include <silkworm/silkrpc/common/log.hpp>

namespace silkworm {

TEST_CASE("print Bytes", "[silkrpc][common][util]") {
    silkworm::Bytes b{};
    CHECK_NOTHROW(silkrpc::null_stream() << b);
}

} // namespace silkworm

namespace silkrpc {

using Catch::Matchers::Message;

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;
using silkworm::kGiga;


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
    silkworm::ByteView bv1{};
    CHECK_NOTHROW(null_stream() << bv1);
    silkworm::ByteView bv2{*silkworm::from_hex("0x0608")};
    CHECK_NOTHROW(null_stream() << bv2);
}

TEST_CASE("print empty address", "[silkrpc][common][util]") {
    evmc::address addr1{};
    CHECK_NOTHROW(null_stream() << addr1);
    evmc::address addr2{0xa872626373628737383927236382161739290870_address};
    CHECK_NOTHROW(null_stream() << addr2);
}

TEST_CASE("print bytes32", "[silkrpc][common][util]") {
    evmc::bytes32 b32_1{};
    CHECK_NOTHROW(null_stream() << b32_1);
    evmc::bytes32 b32_2{0x3763e4f6e4198413383534c763f3f5dac5c5e939f0a81724e3beb96d6e2ad0d5_bytes32};
    CHECK_NOTHROW(null_stream() << b32_2);
}

TEST_CASE("print empty const_buffer", "[silkrpc][common][util]") {
    boost::asio::const_buffer cb{};
    CHECK_NOTHROW(null_stream() << cb);
}

TEST_CASE("print empty vector of const_buffer", "[silkrpc][common][util]") {
    std::vector<boost::asio::const_buffer> v;
    boost::asio::const_buffer cb1{};
    boost::asio::const_buffer cb2{};
    v.push_back(cb1);
    v.push_back(cb2);
    CHECK_NOTHROW(null_stream() << v);
}

TEST_CASE("print Account", "[silkrpc][common][util]") {
    silkworm::Account account{};
    CHECK_NOTHROW(null_stream() << account);
}

TEST_CASE("base64 encode", "[silkrpc][common][util]") {
    uint8_t plain[] = "deadbeaf";
    auto encoded = base64_encode(plain, sizeof(plain), false);
    CHECK(encoded == "ZGVhZGJlYWYA");

    encoded = base64_encode(plain, sizeof(plain), true);
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
    intx::uint256 max_fee_per_gas{silkworm::kEther/10};
    uint64_t gas_limit{8};
    auto check = check_tx_fee_less_cap(1, max_fee_per_gas, gas_limit);
    CHECK(check == true);
}

TEST_CASE("is_replay_protected(tx legacy) returns true", "[silkrpc][common][util]") {
    const silkworm::Transaction txn{
        silkworm::Transaction::Type::kEip2930,
        0,                                                  // nonce
        50'000 * kGiga,                                     // max_priority_fee_per_gas
        50'000 * kGiga,                                     // max_fee_per_gas
        21'000,                                             // gas_limit
        0x5df9b87991262f6ba471f09758cde1c0fc1de734_address, // to
        31337,                                              // value
        {},                                                 // data
        true,                                               // odd_y_parity
        std::nullopt,                                       // chain_id
        intx::from_string<intx::uint256>("0x88ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0"), // r
        intx::from_string<intx::uint256>("0x45e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a"), // s
    };

    auto check = is_replay_protected(txn);
    CHECK(check == false);
}

TEST_CASE("is_replay_protected returns true", "[silkrpc][common][util]") {
    silkworm::Transaction txn{
        silkworm::Transaction::Type::kLegacy,               // type
        0,
        20000000000,
        20000000000,
        uint64_t{0},
        0x0715a7794a1dc8e42615f059dd6e406a6594651a_address,
        intx::uint256{8},
        *silkworm::from_hex("001122aabbcc"),
        false,
        intx::uint256{9},
        intx::uint256{18},
        intx::uint256{36},
        std::vector<silkworm::AccessListEntry>{},
        0x007fb8417eb9ad4d958b050fc3720d5b46a2c053_address
    };
    auto check = is_replay_protected(txn);
    CHECK(check == true);
}

TEST_CASE("is_replay_protected returns false", "[silkrpc][common][util]") {
    const silkworm::Transaction txn{
        silkworm::Transaction::Type::kLegacy,               // type
        0,                                                  // nonce
        50'000 * kGiga,                                     // max_priority_fee_per_gas
        50'000 * kGiga,                                     // max_fee_per_gas
        21'000,                                             // gas_limit
        0x5df9b87991262f6ba471f09758cde1c0fc1de734_address, // to
        31337,                                              // value
        {},                                                 // data
        true,                                               // odd_y_parity
        std::nullopt,                                       // chain_id
        intx::from_string<intx::uint256>("0x88ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0"), // r
        intx::from_string<intx::uint256>("0x45e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a"), // s
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

TEST_CASE("decoding_result_to_string(kNonCanonicalSize)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kNonCanonicalSize) == "rlp: non-canonical size information");
}

TEST_CASE("decoding_result_to_string(kUnexpectedLength)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnexpectedLength) == "rlp: unexpected Length");
}

TEST_CASE("decoding_result_to_string(kUnexpectedString)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnexpectedString) == "rlp: unexpected String");
}

TEST_CASE("decoding_result_to_string(kUnexpectedList)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnexpectedList) == "rlp: element is larger than containing list");
}

TEST_CASE("decoding_result_to_string(kListLengthMismatch)", "[silkrpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kListLengthMismatch) == "rlp: list Length Mismatch");
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
        const auto known_chains{silkworm::get_known_chains_map()};
        for (const auto& [_, known_chain_id] : known_chains) {
            CHECK_NOTHROW(lookup_chain_config(known_chain_id) != nullptr);
        }
    }
    SECTION("lookup unknown chain") {
        CHECK_THROWS_AS(lookup_chain_config(0), std::runtime_error);
    }
}

} // namespace silkrpc

