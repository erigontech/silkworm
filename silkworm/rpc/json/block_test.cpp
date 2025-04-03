// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "block.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/core/common/empty_hashes.hpp>

namespace silkworm::rpc {

TEST_CASE("serialize block with baseFeePerGas", "[rpc][to_json]") {
    silkworm::BlockWithHash block_with_hash{
        {/* Block */
         {
             /* BlockBody */
             .transactions = std::vector<silkworm::Transaction>{},
             .ommers = std::vector<silkworm::BlockHeader>{},
             .withdrawals = std::nullopt,
         },
         {
             /* BlockHeader */
             .parent_hash = 0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32,
             .ommers_hash = 0x474f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126d_bytes32,
             .beneficiary = 0x0715a7794a1dc8e42615f059dd6e406a6594651a_address,
             .state_root = 0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126d_bytes32,
             .transactions_root = 0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126e_bytes32,
             .receipts_root = 0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126f_bytes32,
             .logs_bloom = silkworm::Bloom{},
             .difficulty = intx::uint256{0},
             .number = BlockNum{5},
             .gas_limit = uint64_t{1000000},
             .gas_used = uint64_t{1000000},
             .timestamp = uint64_t{5405021},
             .extra_data = *silkworm::from_hex("0001FF0100"),
             .prev_randao = 0x0000000000000000000000000000000000000000000000000000000000000001_bytes32,
             .nonce = {0, 0, 0, 0, 0, 0, 0, 255},
             .base_fee_per_gas = std::optional<intx::uint256>(0x244428),
         }}};

    auto block_with_hash_shared = std::make_shared<BlockWithHash>();
    *block_with_hash_shared = block_with_hash;

    silkworm::rpc::Block rpc_block{block_with_hash_shared};
    auto body = rpc_block.block_with_hash->block;
    body.transactions.resize(2);
    body.transactions[0].nonce = 172339;
    body.transactions[0].max_priority_fee_per_gas = 50 * kGiga;
    body.transactions[0].max_fee_per_gas = 50 * kGiga;
    body.transactions[0].gas_limit = 90'000;
    body.transactions[0].to = 0xe5ef458d37212a06e3f59d40c454e76150ae7c32_address;
    body.transactions[0].value = 1'027'501'080 * kGiga;
    body.transactions[0].data = {};
    REQUIRE(body.transactions[0].set_v(27));
    body.transactions[0].r =
        intx::from_string<intx::uint256>("0x48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353");
    body.transactions[0].s =
        intx::from_string<intx::uint256>("0x1fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804");

    body.transactions[1].type = TransactionType::kDynamicFee;
    body.transactions[1].nonce = 1;
    body.transactions[1].max_priority_fee_per_gas = 5 * kGiga;
    body.transactions[1].max_fee_per_gas = 30 * kGiga;
    body.transactions[1].gas_limit = 1'000'000;
    body.transactions[1].to = {};
    body.transactions[1].value = 0;
    body.transactions[1].data = *silkworm::from_hex("602a6000556101c960015560068060166000396000f3600035600055");
    REQUIRE(body.transactions[1].set_v(37));
    body.transactions[1].r =
        intx::from_string<intx::uint256>("0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb");
    body.transactions[1].s =
        intx::from_string<intx::uint256>("0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb");

    body.ommers.resize(1);
    body.ommers[0].parent_hash = 0xb397a22bb95bf14753ec174f02f99df3f0bdf70d1851cdff813ebf745f5aeb55_bytes32;
    body.ommers[0].ommers_hash = silkworm::kEmptyListHash;
    body.ommers[0].beneficiary = 0x0c729be7c39543c3d549282a40395299d987cec2_address;
    body.ommers[0].state_root = 0xc2bcdfd012534fa0b19ffba5fae6fc81edd390e9b7d5007d1e92e8e835286e9d_bytes32;
    body.ommers[0].transactions_root = silkworm::kEmptyRoot;
    body.ommers[0].receipts_root = silkworm::kEmptyRoot;
    body.ommers[0].difficulty = 12'555'442'155'599;
    body.ommers[0].number = 13'000'013;
    body.ommers[0].gas_limit = 3'141'592;
    body.ommers[0].gas_used = 0;
    body.ommers[0].timestamp = 1455404305;
    body.ommers[0].prev_randao = 0xf0a53dfdd6c2f2a661e718ef29092de60d81d45f84044bec7bf4b36630b2bc08_bytes32;
    body.ommers[0].nonce[7] = 35;

    nlohmann::json j = rpc_block;
    CHECK(j == R"({
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
        "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "gasLimit":"0xf4240",
        "gasUsed":"0xf4240",
        "timestamp":"0x52795d",
        "size":"0x207",
        "extraData":"0x0001ff0100",
        "mixHash":"0x0000000000000000000000000000000000000000000000000000000000000001",
        "nonce":"0x00000000000000ff",
        "baseFeePerGas":"0x244428",
        "transactions":[],
        "uncles":[]
    })"_json);
}

TEST_CASE("serialize empty block", "[rpc][to_json]") {
    auto block_with_hash = std::make_shared<BlockWithHash>();
    silkworm::rpc::Block block{block_with_hash};
    nlohmann::json j = block;
    CHECK(j == R"({
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
        "hash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "size":"0x1f5",
        "transactions":[],
        "uncles":[]
    })"_json);
}

TEST_CASE("serialize EIP-2718 block", "[rpc][to_json]") {
    const char* rlp_hex{
        "f90319f90211a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd4"
        "1ad312451b948a7413f0a142fd40d49347948888f1f195afa192cfee860698584c030f4c9db1a0ef1552a40b7165c3cd773806b9e0c165"
        "b75356e0314bf0706f279c729f51e017a0e6e49996c7ec59f7a23d22b83239a60151512c65613bf84a0d7da336399ebc4aa0cafe75574d"
        "59780665a97fbfd11365c7545aa8f1abf4e5e12e8243334ef7286bb9010000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000083020000820200832fefd882a410845506eb0796636f6f6c65737420626c6f636b206f6e20636861696ea0bd"
        "4472abb6659ebe3ee06ee4d7b72a00a9f4d001caca51342001075469aff49888a13a5a8c8f2bb1c4f90101f85f800a82c35094095e7bae"
        "a6a6c7c4c2dfeb977efac326af552d870a801ba09bea4c4daac7c7c52e093e6a4c35dbbcf8856f1af7b059ba20253e70848d094fa08a8f"
        "ae537ce25ed8cb5af9adac3f141af69bd515bd2ba031522df09b97dd72b1b89e01f89b01800a8301e24194095e7baea6a6c7c4c2dfeb97"
        "7efac326af552d878080f838f7940000000000000000000000000000000000000001e1a000000000000000000000000000000000000000"
        "0000000000000000000000000001a03dbacc8d0259f2508625e97fdfc57cd85fdd16e5821bc2c10bdd1a52649e8335a0476e10695b183a"
        "87b0aa292a7f4b78ef0c3fbe62aa2c42c84e1d9c3da159ef14c0"};
    silkworm::Bytes rlp_bytes{*silkworm::from_hex(rlp_hex)};
    silkworm::ByteView view{rlp_bytes};

    auto block_with_hash = std::make_shared<BlockWithHash>();
    silkworm::rpc::Block rpc_block{block_with_hash};
    REQUIRE(silkworm::rlp::decode(view, rpc_block.block_with_hash->block));

    nlohmann::json rpc_block_json = rpc_block;
    CHECK(rpc_block_json == R"({
        "difficulty":"0x20000",
        "extraData":"0x636f6f6c65737420626c6f636b206f6e20636861696e",
        "gasLimit":"0x2fefd8",
        "gasUsed":"0xa410",
        "hash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "logsBloom":"0x000000000000000000000000000000000000000000000000000000000000000000000000)"
                            R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
                            R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
                            R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
                            R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
                            R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
                            R"(00000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "miner":"0x8888f1f195afa192cfee860698584c030f4c9db1",
        "mixHash":"0xbd4472abb6659ebe3ee06ee4d7b72a00a9f4d001caca51342001075469aff498",
        "nonce":"0xa13a5a8c8f2bb1c4",
        "number":"0x200",
        "parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "receiptsRoot":"0xcafe75574d59780665a97fbfd11365c7545aa8f1abf4e5e12e8243334ef7286b",
        "sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "size":"0x31c",
        "stateRoot":"0xef1552a40b7165c3cd773806b9e0c165b75356e0314bf0706f279c729f51e017",
        "timestamp":"0x5506eb07",
        "transactions":[
            "0x77b19baa4de67e45a7b26e4a220bccdbb6731885aa9927064e239ca232023215",
            "0x554af720acf477830f996f1bc5d11e54c38aa40042aeac6f66cb66f9084a959d"
        ],
        "transactionsRoot":"0xe6e49996c7ec59f7a23d22b83239a60151512c65613bf84a0d7da336399ebc4a",
        "uncles":[]
    })"_json);
}

}  // namespace silkworm::rpc
