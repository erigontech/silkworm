// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "types.hpp"

#include <optional>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/common/compatibility.hpp>

namespace silkworm::rpc {

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

TEST_CASE("convert zero uint256 to quantity", "[rpc][to_quantity]") {
    intx::uint256 zero_u256{0};
    const auto zero_quantity = to_quantity(zero_u256);
    CHECK(zero_quantity == "0x0");
}

TEST_CASE("convert zero uint256 to quantity(buff)", "[rpc][to_quantity]") {
    intx::uint256 zero_u256{0};
    char zero_quantity[64];
    to_quantity(zero_quantity, zero_u256);
    CHECK(strcmp(zero_quantity, "0x0") == 0);
}

TEST_CASE("convert positive uint256 to quantity", "[rpc][to_quantity]") {
    intx::uint256 positive_u256{100};
    const auto positive_quantity = to_quantity(positive_u256);
    CHECK(positive_quantity == "0x64");
}

TEST_CASE("convert positive uint256 to quantity(buff)", "[rpc][to_quantity]") {
    intx::uint256 positive_u256{100};
    char positive_quantity[64];
    to_quantity(positive_quantity, positive_u256);
    CHECK(strcmp(positive_quantity, "0x64") == 0);
}

TEST_CASE("serialize empty address using to_hex(char *)", "[rpc][to_json]") {
    evmc::address address{};
    char address_zero[64];
    to_hex(address_zero, address.bytes);
    CHECK(strcmp(address_zero, "0x0000000000000000000000000000000000000000") == 0);
}

TEST_CASE("serialize empty address using to_hex(char *) small buffer", "[rpc][to_json]") {
    evmc::address address{};
    char address_zero[10];
    CHECK_THROWS(to_hex(address_zero, address.bytes));
}

TEST_CASE("serialize empty address", "[rpc][to_json]") {
    evmc::address address{};
    nlohmann::json j = address;
    CHECK(j == R"("0x0000000000000000000000000000000000000000")"_json);
}

TEST_CASE("serialize address", "[rpc][to_json]") {
    evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
    nlohmann::json j = address;
    CHECK(j == R"("0x0715a7794a1dc8e42615f059dd6e406a6594651a")"_json);
}

TEST_CASE("deserialize empty address", "[rpc][from_json]") {
    auto j1 = R"("0000000000000000000000000000000000000000")"_json;
    auto address = j1.get<evmc::address>();
    CHECK(address == evmc::address{});
}

TEST_CASE("deserialize address", "[rpc][from_json]") {
    auto j1 = R"("0x0715a7794a1dc8e42615f059dd6e406a6594651a")"_json;
    auto address = j1.get<evmc::address>();
    CHECK(address == evmc::address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address});
}

TEST_CASE("serialize empty bytes32", "[rpc][to_json]") {
    evmc::bytes32 b32{};
    nlohmann::json j = b32;
    CHECK(j == R"("0x0000000000000000000000000000000000000000000000000000000000000000")"_json);
}

TEST_CASE("serialize empty Rlp", "[rpc][to_json]") {
    Rlp rlp;
    nlohmann::json j = rlp;
    CHECK(j == R"("0x")"_json);
}

TEST_CASE("serialize not empty Rlp", "[rpc][to_json]") {
    Rlp rlp;
    rlp.buffer.push_back(0x78);
    rlp.buffer.push_back(0x24);
    nlohmann::json j = rlp;
    CHECK(j == R"("0x7824")"_json);
}

TEST_CASE("serialize AccessListResult with gas_used", "[rpc][to_json]") {
    AccessListResult access_list_result;
    access_list_result.gas_used = 0x1234;
    nlohmann::json j = access_list_result;
    CHECK(j == R"({
        "accessList":[],
        "gasUsed":"0x1234"
    })"_json);
}

TEST_CASE("serialize AccessListResult with error", "[rpc][to_json]") {
    AccessListResult access_list_result;
    access_list_result.gas_used = 0x1234;
    access_list_result.error = "operation reverted";
    nlohmann::json j = access_list_result;
    CHECK(j == R"({
        "accessList":[],
        "error":"operation reverted",
        "gasUsed":"0x1234"
    })"_json);
}

TEST_CASE("serialize TxPoolStatusInfo", "[rpc][to_json]") {
    TxPoolStatusInfo status_info{};
    status_info.pending = 0x7;
    status_info.queued = 0x8;
    status_info.base_fee = 0x9;
    nlohmann::json j = status_info;
    CHECK(j == R"({
        "baseFee":"0x9",
        "pending":"0x7",
        "queued":"0x8"
    })"_json);
}

TEST_CASE("serialize non-empty bytes32", "[rpc][to_json]") {
    evmc::bytes32 b32{0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32};
    nlohmann::json j = b32;
    CHECK(j == R"("0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c")"_json);
}

TEST_CASE("serialize empty block header", "[rpc][to_json]") {
    silkworm::BlockHeader header{};
    rpc::compatibility::set_erigon_json_api_compatibility_required(true);
    nlohmann::json j = header;
    CHECK(j == R"({
        "baseFeePerGas":null,
        "hash": "0xc3bd2d00745c03048a5616146a96f5ff78e54efb9e5b04af208cdaff6f3830ee",
        "parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "sha3Uncles":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "miner":"0x0000000000000000000000000000000000000000",
        "stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "transactionsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "logsBloom":"0x000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(00000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "difficulty":"0x0",
        "nonce":"0x0000000000000000",
        "number":"0x0",
        "gasLimit":"0x0",
        "gasUsed":"0x0",
        "timestamp":"0x0",
        "extraData":"0x",
        "mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "withdrawalsRoot":null,
        "AuRaSeal":null,
        "AuRaStep":0,
        "Verkle":false,
        "VerkleKeyVals":null,
        "VerkleProof":null,
        "requestsHash":null,
        "blobGasUsed":null,
        "excessBlobGas": null,
        "parentBeaconBlockRoot": null
    })"_json);
}

TEST_CASE("serialize block header", "[rpc][to_json]") {
    rpc::compatibility::set_erigon_json_api_compatibility_required(true);
    silkworm::BlockHeader header{
        0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32,
        0x474f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126d_bytes32,
        0x0715a7794a1dc8e42615f059dd6e406a6594651a_address,
        0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126d_bytes32,
        0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126e_bytes32,
        0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126f_bytes32,
        silkworm::Bloom{},
        intx::uint256{0},
        BlockNum{5},
        uint64_t{1000000},
        uint64_t{1000000},
        uint64_t{5405021},
        *silkworm::from_hex("0001FF0100"),
        0x0000000000000000000000000000000000000000000000000000000000000001_bytes32,
        {0, 0, 0, 0, 0, 0, 0, 255}};
    nlohmann::json j = header;
    CHECK(j == R"({
        "baseFeePerGas":null,
        "hash": "0x5e053b099d472a3fc02394243961937ffa008bad0daa81a984a0830ba0beee01",
        "parentHash":"0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c",
        "sha3Uncles":"0x474f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126d",
        "miner":"0x0715a7794a1dc8e42615f059dd6e406a6594651a",
        "stateRoot":"0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126d",
        "transactionsRoot":"0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126e",
        "receiptsRoot":"0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126f",
        "logsBloom":"0x000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(00000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "difficulty":"0x0",
        "number":"0x5",
        "gasLimit":"0xf4240",
        "gasUsed":"0xf4240",
        "timestamp":"0x52795d",
        "extraData":"0x0001ff0100",
        "mixHash":"0x0000000000000000000000000000000000000000000000000000000000000001",
        "nonce":"0x00000000000000ff",
        "withdrawalsRoot":null,
        "AuRaSeal":null,
        "AuRaStep":0,
        "Verkle":false,
        "VerkleKeyVals":null,
        "VerkleProof":null,
        "requestsHash":null,
        "blobGasUsed":null,
        "excessBlobGas": null,
        "parentBeaconBlockRoot": null
    })"_json);
}

TEST_CASE("serialize block header with baseFeePerGas", "[rpc][to_json]") {
    rpc::compatibility::set_erigon_json_api_compatibility_required(true);
    silkworm::BlockHeader header{
        0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32,
        0x474f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126d_bytes32,
        0x0715a7794a1dc8e42615f059dd6e406a6594651a_address,
        0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126d_bytes32,
        0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126e_bytes32,
        0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126f_bytes32,
        silkworm::Bloom{},
        intx::uint256{0},
        BlockNum{5},
        uint64_t{1000000},
        uint64_t{1000000},
        uint64_t{5405021},
        *silkworm::from_hex("0001FF0100"),                                           // extradata
        0x0000000000000000000000000000000000000000000000000000000000000001_bytes32,  // mixhash
        {1, 2, 3, 4, 5, 6, 7, 8},                                                    // nonce
        std::optional<intx::uint256>(1000),                                          // base_fee_per_gas
    };
    nlohmann::json j = header;
    CHECK(j == R"({
        "baseFeePerGas":"0x3e8",
        "hash": "0x5e3a9484b3ee70cc9ae7673051efd0369cfa4126430075921c70255cbdefbe6",
        "parentHash":"0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c",
        "sha3Uncles":"0x474f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126d",
        "miner":"0x0715a7794a1dc8e42615f059dd6e406a6594651a",
        "stateRoot":"0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126d",
        "transactionsRoot":"0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126e",
        "receiptsRoot":"0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126f",
        "logsBloom":"0x000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(00000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "difficulty":"0x0",
        "number":"0x5",
        "gasLimit":"0xf4240",
        "gasUsed":"0xf4240",
        "timestamp":"0x52795d",
        "extraData":"0x0001ff0100",
        "mixHash":"0x0000000000000000000000000000000000000000000000000000000000000001",
        "nonce":"0x0102030405060708",
        "baseFeePerGas":"0x3e8",
        "withdrawalsRoot":null, 
        "AuRaSeal":null,
        "AuRaStep":0,
        "Verkle":false,
        "VerkleKeyVals":null,
        "VerkleProof":null,
        "requestsHash":null,
        "blobGasUsed":null,
        "excessBlobGas": null,
        "parentBeaconBlockRoot": null
    })"_json);
}

TEST_CASE("serialize block with hydrated transactions", "[rpc][to_json]") {
    // 1) build block https://goerli.etherscan.io/block/3529604
    // 1.1) value from table Header for key 000000000035db84
    const char* header_rlp_hex{
        "f9025ca08059c265f40cdb2d3b3245847c21ed154eebf299fd0ff01ee3afded43cdadc45a01dcc4de8dec75d7aab85b567b6ccd41ad312"
        "451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a08add6cb86a4b4a4e5758ce21c8d156e4355917"
        "d29eae7c19f56d4a38f384401da095e5f810e7a45d476d7416fbffbc931473cfdba2b90204e019067bcc6d136dc3a08c3d469c1fbce4e4"
        "144d5e5f91a81baca60b1fb6b5bdcf691b9dc40a5bf21b35b9010004000000000000000000000000040010001000402000000000000000"
        "00000008000020001000000001000000000080000000000010000000000800000000000000000000000000000000000000000000000000"
        "10100000000000000000000008000008000000000000000000000000002000000000000000000000000000040000000000000010000000"
        "00000000000000000000000000000000000000400000000000000000000000020180440020000000080000000000000000000000000000"
        "00000000000000000000000000000000020000000000000000000000000000000000000000000000180000002000004010000880800000"
        "0200400000000000018335db84837a12008308b89a845f7cd33db861476f65726c6920496e697469617469766520417574686f72697479"
        "00000000001f3070be3668d4e3bdd1d08969becd5b06ab0ae4224873453d827a67b3a089ee03c69941418ac300e2c3ca9b5597c7a37959"
        "32a7ff2f907db605a93a88c5b4a800a0000000000000000000000000000000000000000000000000000000000000000088000000000000"
        "0000"};
    silkworm::Bytes header_rlp_bytes{*silkworm::from_hex(header_rlp_hex)};
    silkworm::ByteView header_view{header_rlp_bytes};
    silkworm::BlockHeader header;
    REQUIRE(silkworm::rlp::decode(header_view, header));

    // 1.2) value from table BlockBody for key 000000000035db84c9e65d063911aa583e17bbb7070893482203217caf6d9fbb50265c72e7bf73e5
    const char* body_rlp_hex{"c68341b58302c0"};
    silkworm::Bytes body_rlp_bytes{*silkworm::from_hex(body_rlp_hex)};
    silkworm::ByteView body_view{body_rlp_bytes};
    const auto body_for_storage{silkworm::unwrap_or_throw(silkworm::decode_stored_block_body(body_view))};
    REQUIRE(body_for_storage.txn_count == 2);
    REQUIRE(body_for_storage.base_txn_id == 0x41b583);

    // 1.3) value from table BlockTransaction for key 000000000041b583 and 000000000041b584
    const char* tx1_rlp_hex{
        "f87080843b9aca00830c350094fa365f1384e4eaf6d59f353c782af3ea42feaab988015c2a7b13fd000084d0e30db02ea06b0df7c31119"
        "b257e7faeb391984f199c8da817b14279ac09262bdf3493599a6a00c729ce28ec0030002490d6217a8b50041495925142e70fa1b77e465"
        "eab97c4b"};
    silkworm::Bytes tx1_rlp_bytes{*silkworm::from_hex(tx1_rlp_hex)};
    silkworm::ByteView tx1_view{tx1_rlp_bytes};
    silkworm::Transaction tx1;
    REQUIRE(silkworm::rlp::decode(tx1_view, tx1));
    const char* tx2_rlp_hex{
        "f901aa02843b9aca008304fa4a9431af35bdfa897cd42b204c003560c385d444707580b901449b4e463400000000000000000000000000"
        "0000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c081c2ac5b"
        "ba256c88daa744c9caa7d6c99c32c1bc0c07bdca87bd2a054118c47b000000000000000000000000000000000000000000000000000000"
        "0000000030a5a151a2320abaab98cfa8366fc326fb6f45cf1c93697191ec1370e1caca0fc6237e3bc5328755ae66bc5ddb141f0cb10000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060a4dcd35675e049ea5b"
        "58d9567f8029669d4cdbe72511d330d96a578e2714f1c9db00f6a9babc217b250fc7f217b0261506727657b420d9e05adc73675390ce2e"
        "b1e1aef3bac7d1b4b424c9dc07cdcac2729eabdb81c857325e20202ea24761601ba01d8e665abc1278a9526aaf4c604f75b293e43ccf9d"
        "c72918a633af584b73425ba07f8913ecd5db0e98d48097abefd7b2fa954d7cf1514496b870b8a1335034df4d"};
    silkworm::Bytes tx2_rlp_bytes{*silkworm::from_hex(tx2_rlp_hex)};
    silkworm::ByteView tx2_view{tx2_rlp_bytes};
    silkworm::Transaction tx2;
    REQUIRE(silkworm::rlp::decode(tx2_view, tx2));

    silkworm::BlockWithHash block_with_hash{
        // BlockWithHash
        /*.block =*/{
            // Block
            {
                // BlockBody
                .transactions = std::vector<silkworm::Transaction>{tx1, tx2},
                .ommers = std::vector<silkworm::BlockHeader>{},
                .withdrawals = std::nullopt,
            },
            /*.header =*/header,
        },
        /*.hash =*/0xc9e65d063911aa583e17bbb7070893482203217caf6d9fbb50265c72e7bf73e5_bytes32,
    };

    auto block_with_hash_shared = std::make_shared<BlockWithHash>();
    *block_with_hash_shared = block_with_hash;
    silkworm::rpc::Block rpc_block{block_with_hash_shared, /* full_tx */ true};

    nlohmann::json rpc_block_json = rpc_block;
    CHECK(rpc_block_json == R"({
        "difficulty":"0x1",
        "extraData":"0x476f65726c6920496e697469617469766520417574686f7269747900000000001f3070be3)"
                            R"(668d4e3bdd1d08969becd5b06ab0ae4224873453d827a67b3a089ee03c69941418ac300e2c3c)"
                            R"(a9b5597c7a3795932a7ff2f907db605a93a88c5b4a800",
        "gasLimit":"0x7a1200",
        "gasUsed":"0x8b89a",
        "hash":"0xc9e65d063911aa583e17bbb7070893482203217caf6d9fbb50265c72e7bf73e5",
        "logsBloom":"0x040000000000000000000000000400100010004020000000000000000000000800002000)"
                            R"(100000000100000000008000000000001000000000080000000000000000000000000000)"
                            R"(000000000000000000000010100000000000000000000008000008000000000000000000)"
                            R"(000000002000000000000000000000000000040000000000000010000000000000000000)"
                            R"(000000000000000000000000004000000000000000000000000201804400200000000800)"
                            R"(000000000000000000000000000000000000000000000000000000000002000000000000)"
                            R"(000000000000000000000000000000000018000000200000401000088080000002004000)"
                            R"(00000000",
        "miner":"0x0000000000000000000000000000000000000000",
        "mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "nonce":"0x0000000000000000",
        "number":"0x35db84",
        "parentHash":"0x8059c265f40cdb2d3b3245847c21ed154eebf299fd0ff01ee3afded43cdadc45",
        "receiptsRoot":"0x8c3d469c1fbce4e4144d5e5f91a81baca60b1fb6b5bdcf691b9dc40a5bf21b35",
        "sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "size":"0x485",
        "stateRoot":"0x8add6cb86a4b4a4e5758ce21c8d156e4355917d29eae7c19f56d4a38f384401d",
        "timestamp":"0x5f7cd33d",
        "transactions":[
            {
                "blockHash":"0xc9e65d063911aa583e17bbb7070893482203217caf6d9fbb50265c72e7bf73e5",
                "blockNumber":"0x35db84",
                "from":"0x4ed7fae4af36f11ac28275a98ca1d131e91bb6cd",
                "gas":"0xc3500",
                "gasPrice":"0x3b9aca00",
                "hash":"0xa52100232ad8abc15bdcd95b071194d2084781f88a71974eef7292c8513a03b4",
                "input":"0xd0e30db0",
                "nonce":"0x0",
                "r":"0x6b0df7c31119b257e7faeb391984f199c8da817b14279ac09262bdf3493599a6",
                "s":"0xc729ce28ec0030002490d6217a8b50041495925142e70fa1b77e465eab97c4b",
                "to":"0xfa365f1384e4eaf6d59f353c782af3ea42feaab9",
                "transactionIndex":"0x0",
                "type":"0x0",
                "v":"0x2e",
                "chainId":"0x5",
                "value":"0x15c2a7b13fd0000"
            },
            {
                "blockHash":"0xc9e65d063911aa583e17bbb7070893482203217caf6d9fbb50265c72e7bf73e5",
                "blockNumber":"0x35db84",
                "from":"0xab2e6a1020c511615f82155259086717802d1474",
                "gas":"0x4fa4a",
                "gasPrice":"0x3b9aca00",
                "hash":"0x81d69137fe27a549e957c2dd3d54f374a019bf12409ca44fb9e01dc82ac7e925",
                "input":"0x9b4e463400000000000000000000000000000000000000000000000000000000000000600)"
                            R"(0000000000000000000000000000000000000000000000000000000000000c081c2ac5bba256)"
                            R"(c88daa744c9caa7d6c99c32c1bc0c07bdca87bd2a054118c47b0000000000000000000000000)"
                            R"(000000000000000000000000000000000000030a5a151a2320abaab98cfa8366fc326fb6f45c)"
                            R"(f1c93697191ec1370e1caca0fc6237e3bc5328755ae66bc5ddb141f0cb100000000000000000)"
                            R"(0000000000000000000000000000000000000000000000000000000000000000000000000000)"
                            R"(060a4dcd35675e049ea5b58d9567f8029669d4cdbe72511d330d96a578e2714f1c9db00f6a9b)"
                            R"(abc217b250fc7f217b0261506727657b420d9e05adc73675390ce2eb1e1aef3bac7d1b4b424c)"
                            R"(9dc07cdcac2729eabdb81c857325e20202ea2476160",
                "nonce":"0x2",
                "r":"0x1d8e665abc1278a9526aaf4c604f75b293e43ccf9dc72918a633af584b73425b",
                "s":"0x7f8913ecd5db0e98d48097abefd7b2fa954d7cf1514496b870b8a1335034df4d",
                "to":"0x31af35bdfa897cd42b204c003560c385d4447075",
                "transactionIndex":"0x1",
                "type":"0x0",
                "v":"0x1b",
                "value":"0x0"
            }
        ],
        "transactionsRoot":"0x95e5f810e7a45d476d7416fbffbc931473cfdba2b90204e019067bcc6d136dc3",
        "uncles":[]
    })"_json);
}

TEST_CASE("serialize block body with ommers", "[rpc][to_json]") {
    // https://etherscan.io/block/3
    const char* rlp_hex{
        "f90219c0f90215f90212a0d4e56740f876aef8c010b86a40d5f56745a118d090"
        "6a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b"
        "948a7413f0a142fd40d4934794c8ebccc5f5689fa8659d83713341e5ad193494"
        "48a01e6e030581fd1873b4784280859cd3b3c04aa85520f08c304cf5ee63d393"
        "5adda056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e3"
        "63b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5"
        "e363b421b9010000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "000000000000008503ff80000001821388808455ba42429a5961746573205261"
        "6e64616c6c202d2045746865724e696e6a61a0f8c94dfe61cf26dcdf8cffeda3"
        "37cf6a903d65c449d7691a022837f6e2d994598868b769c5451a7aea"};
    silkworm::Bytes rlp_bytes{*silkworm::from_hex(rlp_hex)};
    silkworm::ByteView in{rlp_bytes};

    auto block_with_hash_shared = std::make_shared<BlockWithHash>();
    silkworm::rpc::Block rpc_block{block_with_hash_shared};
    silkworm::BlockBody block_body;
    REQUIRE(silkworm::rlp::decode(in, block_body));
    rpc_block.block_with_hash->block.ommers = block_body.ommers;

    nlohmann::json rpc_block_json = rpc_block;
    CHECK(rpc_block_json == R"({
        "difficulty":"0x0",
        "extraData":"0x",
        "gasLimit":"0x0",
        "gasUsed":"0x0",
        "hash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "logsBloom":"0x000000000000000000000000000000000000000000000000000000000000000000000000)"
                            R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
                            R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
                            R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
                            R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
                            R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
                            R"(00000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "miner":"0x0000000000000000000000000000000000000000",
        "mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "nonce":"0x0000000000000000",
        "number":"0x0",
        "parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "sha3Uncles":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "size":"0x40c",
        "stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "timestamp":"0x0",
        "transactions":[],
        "transactionsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "uncles":["0x5cd50096dbb856a6d1befa6de8f9c20decb299f375154427d90761dc0b101109"]
    })"_json);
}

TEST_CASE("serialize filled SyncingData", "[rpc][to_json]") {
    SyncingData syncing_data{};
    StageData stage_data;

    syncing_data.current_block = "0x1";
    syncing_data.max_block = "0x2";
    stage_data.stage_name = "stage1";
    stage_data.block_num = "0x3";
    syncing_data.stages.push_back(stage_data);
    stage_data.stage_name = "stage2";
    stage_data.block_num = "0x4";
    syncing_data.stages.push_back(stage_data);

    nlohmann::json j = syncing_data;
    CHECK(j == R"({
      "currentBlock":"0x1","highestBlock":"0x2","stages":[{"block_number":"0x3","stage_name":"stage1"},{"block_number":"0x4","stage_name":"stage2"}]
    })"_json);
}

TEST_CASE("serialize error", "[rpc][to_json]") {
    Error err{100, {"generic error"}};
    nlohmann::json j = err;
    CHECK(j == R"({
        "code":100,
        "message":"generic error"
    })"_json);
}

TEST_CASE("serialize std::set<evmc::address>", "[rpc][to_json]") {
    std::set<evmc::address> addresses;

    SECTION("empty addresses set") {
        nlohmann::json j;
        to_json(j, addresses);
        CHECK(j == R"([])"_json);
    }

    SECTION("filled addresses set") {
        addresses.insert(0x07aaec0b237ccf56b03a7c43c1c7a783da560642_address);
        nlohmann::json j;
        to_json(j, addresses);
        CHECK(j == R"(["0x07aaec0b237ccf56b03a7c43c1c7a783da560642"])"_json);
    }
}

TEST_CASE("deserialize block_num_or_hash", "[silkworm::json][from_json]") {
    SECTION("as hash") {
        auto json = R"("0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c")"_json;
        auto block_num_or_hash = json.get<BlockNumOrHash>();

        CHECK(block_num_or_hash.is_hash() == true);
        CHECK(block_num_or_hash.is_number() == false);
        CHECK(block_num_or_hash.is_tag() == false);
        CHECK(block_num_or_hash.hash() == 0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32);
    }

    SECTION("as decimal number string") {
        auto json = R"("1966")"_json;
        auto block_num_or_hash = json.get<BlockNumOrHash>();

        CHECK(block_num_or_hash.is_hash() == false);
        CHECK(block_num_or_hash.is_number() == true);
        CHECK(block_num_or_hash.is_tag() == false);
        CHECK(block_num_or_hash.number() == 1966);
    }

    SECTION("as hex number string") {
        auto json = R"("0x374f3")"_json;
        auto block_num_or_hash = json.get<BlockNumOrHash>();

        CHECK(block_num_or_hash.is_hash() == false);
        CHECK(block_num_or_hash.is_number() == true);
        CHECK(block_num_or_hash.is_tag() == false);
        CHECK(block_num_or_hash.number() == 0x374f3);
    }

    SECTION("as tag string") {
        auto json = R"("latest")"_json;
        auto block_num_or_hash = json.get<BlockNumOrHash>();

        CHECK(block_num_or_hash.is_hash() == false);
        CHECK(block_num_or_hash.is_number() == false);
        CHECK(block_num_or_hash.is_tag() == true);
        CHECK(block_num_or_hash.tag() == "latest");
    }

    SECTION("as number") {
        auto json = R"(123456)"_json;
        auto block_num_or_hash = json.get<BlockNumOrHash>();

        CHECK(block_num_or_hash.is_hash() == false);
        CHECK(block_num_or_hash.is_number() == true);
        CHECK(block_num_or_hash.is_tag() == false);
        CHECK(block_num_or_hash.number() == 123456);
    }
}

TEST_CASE("serialize zero forks", "[silkworm::json][to_json]") {
    auto cc = ChainConfig::from_json(R"({"chainId":1,"ethash":{}})"_json);
    REQUIRE(cc.has_value());
    cc->genesis_hash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;
    Forks f{*cc};
    nlohmann::json j = f;
    CHECK(j == R"({
        "genesis":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "heightForks":[],
        "timeForks":[]
    })"_json);
}

TEST_CASE("serialize forks", "[silkworm::json][to_json]") {
    auto cc = ChainConfig::from_json(R"({
        "berlinBlock":12244000,
        "byzantiumBlock":4370000,
        "chainId":1,
        "constantinopleBlock":7280000,
        "daoForkBlock":1920000,
        "eip150Block":2463000,
        "eip155Block":2675000,
        "ethash":{},
        "homesteadBlock":1150000,
        "istanbulBlock":9069000,
        "londonBlock":12965000,
        "muirGlacierBlock":9200000,
        "petersburgBlock":7280000,
        "shanghaiTime":1678832736
    })"_json);
    REQUIRE(cc.has_value());
    cc->genesis_hash = 0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32;
    Forks f{*cc};
    nlohmann::json j = f;
    CHECK(j == R"({
        "genesis":"0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c",
        "heightForks":[1150000,1920000,2463000,2675000,4370000,7280000,9069000,9200000,12244000,12965000],
        "timeForks":[1678832736]
    })"_json);
}

TEST_CASE("serialize empty issuance", "[silkworm::json][to_json]") {
    silkworm::rpc::Issuance issuance{};
    nlohmann::json j = issuance;
    CHECK(j == R"({
        "blockReward":null,
        "uncleReward":null,
        "issuance":null,
        "burnt":null,
        "tips":null,
        "totalBurnt":null,
        "totalIssued":null
    })"_json);
}

TEST_CASE("serialize chain_traffic", "[silkworm::json][to_json]") {
    silkworm::rpc::ChainTraffic chain_traffic{4, 5};
    nlohmann::json j = chain_traffic;
    CHECK(j == R"({
        "cumulativeGasUsed":"0x4",
        "cumulativeTransactionsCount":"0x5"
    })"_json);
}

TEST_CASE("serialize issuance", "[silkworm::json][to_json]") {
    silkworm::rpc::Issuance issuance{
        "0x0",
        "0x0",
        "0x0",
        "0x0",
        "0x0",
        "0x0",
        "0x0"};
    nlohmann::json j = issuance;
    CHECK(j == R"({
        "blockReward":"0x0",
        "uncleReward":"0x0",
        "issuance":"0x0",
        "burnt":"0x0",
        "tips":"0x0",
        "totalBurnt":"0x0",
        "totalIssued":"0x0"
    })"_json);
}

TEST_CASE("serialize ForkChoiceUpdatedReplyV1", "[silkworm::json][to_json]") {
    silkworm::rpc::PayloadStatus payload_status{
        .status = "VALID",
        .latest_valid_hash = 0x0000000000000000000000000000000000000000000000000000000000000040_bytes32,
        .validation_error = "some error"};
    silkworm::rpc::ForkChoiceUpdatedReply forkchoice_update_reply{
        .payload_status = payload_status,
        .payload_id = 0x1};

    nlohmann::json j = forkchoice_update_reply;
    CHECK(j == R"({
        "payloadStatus": {
            "status":"VALID",
            "latestValidHash":"0x0000000000000000000000000000000000000000000000000000000000000040",
            "validationError":"some error"
        },
        "payloadId":"0x0000000000000001"
    })"_json);
}

TEST_CASE("serialize PayloadStatusV1", "[silkworm::json][to_json]") {
    silkworm::rpc::PayloadStatus payload_status{
        .status = "VALID",
        .latest_valid_hash = 0x0000000000000000000000000000000000000000000000000000000000000040_bytes32,
        .validation_error = "some error"};
    nlohmann::json j = payload_status;
    CHECK(j == R"({
        "status":"VALID",
        "latestValidHash":"0x0000000000000000000000000000000000000000000000000000000000000040",
        "validationError":"some error"
    })"_json);
}

TEST_CASE("make empty json content", "[silkworm::json][make_json_content]") {
    const nlohmann::json request = R"({
        "id":0
    })"_json;
    const auto j = make_json_content(request, {});
    CHECK(j == R"({
        "jsonrpc":"2.0",
        "id":0,
        "result":null
    })"_json);
}

TEST_CASE("make json content", "[silkworm::json][make_json_content]") {
    const nlohmann::json request = R"({
        "id":123
    })"_json;
    nlohmann::json json_result = {{"currency", "ETH"}, {"value", 4.2}};
    const auto j = make_json_content(request, json_result);
    CHECK(j == R"({
        "jsonrpc":"2.0",
        "id":123,
        "result":{"currency":"ETH","value":4.2}
    })"_json);
}

TEST_CASE("make empty json error", "[silkworm::json][make_json_error]") {
    const nlohmann::json request = R"({
        "id":0
    })"_json;
    const auto j = make_json_error(request, 0, "");
    CHECK(j == R"({
        "jsonrpc":"2.0",
        "id":0,
        "error":{"code":0,"message":""}
    })"_json);
}

TEST_CASE("make empty json revert error", "[silkworm::json][make_json_error]") {
    const nlohmann::json request = R"({
        "id":0
    })"_json;
    const auto j = make_json_error(request, {{0, ""}, silkworm::Bytes{}});
    CHECK(j == R"({
        "jsonrpc":"2.0",
        "id":0,
        "error":{"code":0,"message":"","data":"0x"}
    })"_json);
}

TEST_CASE("make json error", "[silkworm::json][make_json_error]") {
    const nlohmann::json request = R"({
        "id":123
    })"_json;

    const auto j = make_json_error(request, -32000, "revert");
    CHECK(j == R"({
        "jsonrpc":"2.0",
        "id":123,
        "error":{"code":-32000,"message":"revert"}
    })"_json);
}

TEST_CASE("make json revert error", "[silkworm::json][make_json_error]") {
    const nlohmann::json request = R"({
        "id":123
    })"_json;

    const auto j = make_json_error(request, {{3, "execution reverted: Ownable: caller is not the owner"}, *silkworm::from_hex("0x00010203")});
    CHECK(j == R"({
        "jsonrpc":"2.0",
        "id":123,
        "error":{"code":3,"message":"execution reverted: Ownable: caller is not the owner","data":"0x00010203"}
    })"_json);
}

}  // namespace silkworm::rpc
