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

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/test_util/null_stream.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

TEST_CASE("calculate hash of byte array", "[rpc][common][util]") {
    const auto eth_hash{hash_of(silkworm::ByteView{})};
    CHECK(silkworm::to_bytes32(silkworm::ByteView{eth_hash.bytes, silkworm::kHashLength}) == silkworm::kEmptyHash);
}

TEST_CASE("calculate hash of transaction", "[rpc][common][util]") {
    const auto eth_hash{hash_of_transaction(silkworm::Transaction{})};
    CHECK(silkworm::to_bytes32(silkworm::ByteView{eth_hash.bytes, silkworm::kHashLength}) == 0x3763e4f6e4198413383534c763f3f5dac5c5e939f0a81724e3beb96d6e2ad0d5_bytes32);
}

TEST_CASE("print empty address", "[rpc][common][util]") {
    evmc::address addr1{};
    CHECK_NOTHROW(test_util::null_stream() << addr1);
    evmc::address addr2{0xa872626373628737383927236382161739290870_address};
    CHECK_NOTHROW(test_util::null_stream() << addr2);
}

TEST_CASE("print bytes32", "[rpc][common][util]") {
    evmc::bytes32 b32_1{};
    CHECK_NOTHROW(test_util::null_stream() << to_hex(b32_1));
    evmc::bytes32 b32_2{0x3763e4f6e4198413383534c763f3f5dac5c5e939f0a81724e3beb96d6e2ad0d5_bytes32};
    CHECK_NOTHROW(test_util::null_stream() << to_hex(b32_2));
}

TEST_CASE("print empty const_buffer", "[rpc][common][util]") {
    boost::asio::const_buffer cb{};
    CHECK_NOTHROW(test_util::null_stream() << cb);
}

TEST_CASE("print empty vector of const_buffer", "[rpc][common][util]") {
    std::vector<boost::asio::const_buffer> v;
    boost::asio::const_buffer cb1{};
    boost::asio::const_buffer cb2{};
    v.push_back(cb1);
    v.push_back(cb2);
    CHECK_NOTHROW(test_util::null_stream() << v);
}

TEST_CASE("print Account", "[rpc][common][util]") {
    silkworm::Account account{};
    CHECK_NOTHROW(test_util::null_stream() << account);
}

TEST_CASE("base64 encode", "[rpc][common][util]") {
    uint8_t plain[] = "deadbeaf";
    auto encoded = base64_encode({plain, sizeof(plain)}, false);
    CHECK(encoded == "ZGVhZGJlYWYA");

    encoded = base64_encode({plain, sizeof(plain)}, true);
    CHECK(encoded == "ZGVhZGJlYWYA");
}

TEST_CASE("check_tx_fee_less_cap(cap=0) returns true", "[rpc][common][util]") {
    intx::uint256 max_fee_per_gas{silkworm::kEther * 1};
    uint64_t gas_limit{20};
    auto check = check_tx_fee_less_cap(0, max_fee_per_gas, gas_limit);
    CHECK(check == true);
}

TEST_CASE("check_tx_fee_less_cap returns true", "[rpc][common][util]") {
    intx::uint256 max_fee_per_gas{silkworm::kEther * 1};
    uint64_t gas_limit{20};
    auto check = check_tx_fee_less_cap(1, max_fee_per_gas, gas_limit);
    CHECK(check == false);
}

TEST_CASE("check_tx_fee_less_cap returns false", "[rpc][common][util]") {
    intx::uint256 max_fee_per_gas{silkworm::kEther / 10};
    uint64_t gas_limit{8};
    auto check = check_tx_fee_less_cap(1, max_fee_per_gas, gas_limit);
    CHECK(check == true);
}

TEST_CASE("is_replay_protected(tx legacy) returns true", "[rpc][common][util]") {
    Transaction txn{};
    txn.type = TransactionType::kAccessList;
    txn.nonce = 0;
    txn.max_priority_fee_per_gas = 50'000 * kGiga;
    txn.max_fee_per_gas = 50'000 * kGiga;
    txn.gas_limit = 21'000;
    txn.to = 0x5df9b87991262f6ba471f09758cde1c0fc1de734_address;
    txn.value = 31337;
    txn.odd_y_parity = true;
    txn.r = intx::from_string<intx::uint256>("0x88ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0");
    txn.s = intx::from_string<intx::uint256>("0x45e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a");
    auto check = is_replay_protected(txn);
    CHECK(check == true);
}

TEST_CASE("is_replay_protected returns true", "[rpc][common][util]") {
    Transaction txn{};
    txn.type = TransactionType::kLegacy;
    txn.chain_id = 9;
    txn.nonce = 0;
    txn.max_priority_fee_per_gas = 20000000000;
    txn.max_fee_per_gas = 20000000000;
    txn.gas_limit = 0;
    txn.to = 0x0715a7794a1dc8e42615f059dd6e406a6594651a_address;
    txn.value = 8;
    txn.data = *from_hex("001122aabbcc");
    txn.odd_y_parity = false;
    txn.r = 18;
    txn.s = 36;
    txn.set_sender(0x007fb8417eb9ad4d958b050fc3720d5b46a2c053_address);
    auto check = is_replay_protected(txn);
    CHECK(check == true);
}

TEST_CASE("is_replay_protected returns false", "[rpc][common][util]") {
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
    auto check = is_replay_protected(txn);
    CHECK(check == false);
}

TEST_CASE("decoding_result_to_string(kOverflow)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kOverflow) == "rlp: uint overflow");
}

TEST_CASE("decoding_result_to_string(kLeadingZero)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kLeadingZero) == "rlp: leading Zero");
}

TEST_CASE("decoding_result_to_string(kInputTooShort)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kInputTooShort) == "rlp: value size exceeds available input length");
}

TEST_CASE("decoding_result_to_string(kInputTooLong)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kInputTooLong) == "rlp: input exceeds encoded length");
}

TEST_CASE("decoding_result_to_string(kNonCanonicalSize)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kNonCanonicalSize) == "rlp: non-canonical size information");
}

TEST_CASE("decoding_result_to_string(kUnexpectedLength)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnexpectedLength) == "rlp: unexpected Length");
}

TEST_CASE("decoding_result_to_string(kUnexpectedString)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnexpectedString) == "rlp: expected list, got string instead");
}

TEST_CASE("decoding_result_to_string(kUnexpectedList)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnexpectedList) == "rlp: expected string, got list instead");
}

TEST_CASE("decoding_result_to_string(kUnexpectedListElements)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnexpectedListElements) == "rlp: unexpected list element(s)");
}

TEST_CASE("decoding_result_to_string(kInvalidVInSignature)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kInvalidVInSignature) == "rlp: invalid V in signature");
}

TEST_CASE("decoding_result_to_string(kUnsupportedTransactionType)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnsupportedTransactionType) == "rlp: unknown tx type prefix");
}

TEST_CASE("decoding_result_to_string(kInvalidFieldset)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kInvalidFieldset) == "rlp: invalid field set");
}

TEST_CASE("decoding_result_to_string(kUnexpectedEip2718Serialization)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kUnexpectedEip2718Serialization) == "rlp: unexpected EIP-2178 serialization");
}

TEST_CASE("decoding_result_to_string(kInvalidHashesLength)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kInvalidHashesLength) == "rlp: invalid hashes length");
}

TEST_CASE("decoding_result_to_string(kInvalidMasksSubsets)", "[rpc][common][util]") {
    CHECK(decoding_result_to_string(silkworm::DecodingError::kInvalidMasksSubsets) == "rlp: invalid masks subsets");
}

TEST_CASE("lookup_chain_config", "[rpc][common][util]") {
    SECTION("lookup known chain") {
        for (const auto& [_, known_chain_id] : kKnownChainNameToId) {
            CHECK_NOTHROW(lookup_chain_config(known_chain_id) != nullptr);
        }
    }
    SECTION("lookup unknown chain") {
        CHECK_THROWS_AS(lookup_chain_config(0), std::runtime_error);
    }
}

TEST_CASE("get_opcode_name") {
    SECTION("valid op_code") {
        auto op_code_name = get_opcode_name(0x00);
        CHECK(op_code_name == "STOP");
    }
    SECTION("not existent op_code") {
        auto op_code_name = get_opcode_name(0x0d);
        CHECK(!op_code_name.has_value());
    }
    SECTION("DIFFICULTY/PREVRANDAO opcode") {
        auto op_code_name = get_opcode_name(0x44);
        CHECK(op_code_name == "DIFFICULTY");
    }
}

TEST_CASE("get_opcode_hex") {
    SECTION("1 digit opcode") {
        auto op_code = get_opcode_hex(0x00);
        CHECK(op_code == "0x0");

        op_code = get_opcode_hex(0x0a);
        CHECK(op_code == "0xa");
    }
    SECTION("2 digit opcode") {
        auto op_code = get_opcode_hex(0x10);
        CHECK(op_code == "0x10");

        op_code = get_opcode_hex(0x4f);
        CHECK(op_code == "0x4f");
    }
}

}  // namespace silkworm
