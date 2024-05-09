/*
   Copyright 2024 The Silkworm Authors

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

#include "block.hpp"

#include <string_view>

#include <catch2/catch.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/node/test_util/fixture.hpp>

namespace silkworm::execution::grpc {

TEST_CASE("deserialize_hex_as_bytes", "[node][execution][grpc]") {
    const test_util::Fixtures<std::string_view, std::vector<Bytes>> fixtures{
        {"", {Bytes{}}},
        {"0x01", {Bytes{0x01}}},
        {"0x0102", {Bytes{0x01, 0x02}}},
    };
    for (const auto& [hex, expected_byte_vector] : fixtures) {
        SECTION("hex bytes: " + std::to_string(expected_byte_vector.size())) {
            std::vector<Bytes> bb;
            CHECK_NOTHROW(deserialize_hex_as_bytes(hex, bb));
            CHECK(bb == expected_byte_vector);
        }
    }
    SECTION("invalid hex") {
        std::vector<Bytes> bb;
        CHECK_NOTHROW(deserialize_hex_as_bytes("00zz", bb));
        CHECK(bb.empty());
    }
}

static constexpr auto parent_hash{0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32};
static constexpr auto ommers_hash{0x474f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126d_bytes32};
static auto beneficiary{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
static auto state_root{0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126d_bytes32};
static auto transactions_root{0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126e_bytes32};
static auto receipts_root{0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126f_bytes32};
static auto difficulty{intx::uint256{1234}};
static auto block_number{5u};
static auto gas_limit{1000000u};
static auto gas_used{1000000u};
static auto timestamp{5405021u};
static const Bytes extra_data{*from_hex("0001FF0100")};
static auto prev_randao{0x0000000000000000000000000000000000000000000000000000000000000001_bytes32};
static auto nonce{255u};
static auto nonce_as_array{std::array<uint8_t, 8>{0, 0, 0, 0, 0, 0, 0, 255}};
static auto base_fee_per_gas{0x244428u};

static ::execution::Header sample_proto_header() {
    ::execution::Header header;
    header.set_allocated_parent_hash(rpc::H256_from_bytes32(parent_hash).release());
    header.set_allocated_ommer_hash(rpc::H256_from_bytes32(ommers_hash).release());
    header.set_allocated_coinbase(rpc::H160_from_address(beneficiary).release());
    header.set_allocated_state_root(rpc::H256_from_bytes32(state_root).release());
    header.set_allocated_transaction_hash(rpc::H256_from_bytes32(transactions_root).release());
    header.set_allocated_receipt_root(rpc::H256_from_bytes32(receipts_root).release());
    header.set_allocated_difficulty(rpc::H256_from_uint256(difficulty).release());
    header.set_block_number(block_number);
    header.set_gas_limit(gas_limit);
    header.set_gas_used(gas_used);
    header.set_timestamp(timestamp);
    header.set_extra_data(byte_ptr_cast(extra_data.data()), extra_data.size());
    header.set_allocated_prev_randao(rpc::H256_from_bytes32(prev_randao).release());
    header.set_nonce(nonce);
    header.set_allocated_base_fee_per_gas(rpc::H256_from_uint256(base_fee_per_gas).release());
    return header;
}

static BlockHeader sample_block_header() {
    return {
        .parent_hash = parent_hash,
        .ommers_hash = ommers_hash,
        .beneficiary = beneficiary,
        .state_root = state_root,
        .transactions_root = transactions_root,
        .receipts_root = receipts_root,
        .difficulty = difficulty,
        .number = block_number,
        .gas_limit = gas_limit,
        .gas_used = gas_used,
        .timestamp = timestamp,
        .extra_data = extra_data,
        .prev_randao = prev_randao,
        .nonce = nonce_as_array,
        .base_fee_per_gas = base_fee_per_gas,
    };
}

TEST_CASE("header_from_proto", "[node][execution][grpc]") {
    const test_util::Fixtures<::execution::Header, BlockHeader> fixtures{
        {{}, {}},
        {sample_proto_header(), sample_block_header()},
    };
    for (const auto& [proto_header, expected_block_header] : fixtures) {
        SECTION("header: " + std::to_string(proto_header.block_number())) {
            BlockHeader header;
            CHECK_NOTHROW(header_from_proto(proto_header, header));
            CHECK(header == expected_block_header);
            CHECK(header_from_proto(proto_header) == expected_block_header);
        }
    }
}

TEST_CASE("convertibility", "[node][execution][grpc]") {
    const test_util::Fixtures<::execution::Header, BlockHeader> fixtures{
        {{}, {}},
        {sample_proto_header(), sample_block_header()},
    };
    for (const auto& [expected_proto_header, expected_block_header] : fixtures) {
        SECTION("header: " + std::to_string(expected_proto_header.block_number())) {
            const BlockHeader header = header_from_proto(expected_proto_header);
            CHECK(header == expected_block_header);
            ::execution::Header proto_header;
            proto_from_header(header, &proto_header);
            // CHECK(proto_header == expected_proto_header);  // requires operator== for ::execution::Header
            CHECK(header_from_proto(proto_header) == expected_block_header);
        }
    }
}

}  // namespace silkworm::execution::grpc
