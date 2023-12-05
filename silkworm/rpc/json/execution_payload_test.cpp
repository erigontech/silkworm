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

#include "execution_payload.hpp"

#include <catch2/catch.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc {

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

TEST_CASE("serialize ExecutionPayloadV1", "[silkworm][rpc][json]") {
    ExecutionPayload payload_v1{
        .version = ExecutionPayload::V1,
        .number = 0x1,
        .timestamp = 0x5,
        .gas_limit = 0x1c9c380,
        .suggested_fee_recipient = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address,
        .state_root = 0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45_bytes32,
        .receipts_root = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32,
        .parent_hash = 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32,
        .block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
        .prev_randao = 0x0000000000000000000000000000000000000000000000000000000000000001_bytes32,
        .base_fee = 0x7,
        .transactions = {*silkworm::from_hex("0xf92ebdeab45d368f6354e8c5a8ac586c")},
    };
    CHECK(nlohmann::json(payload_v1) == R"({
        "parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
        "feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
        "stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45",
        "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000001",
        "blockNumber":"0x1",
        "gasLimit":"0x1c9c380",
        "gasUsed":"0x0",
        "timestamp":"0x5",
        "extraData":"0x",
        "baseFeePerGas":"0x7",
        "blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
        "transactions":["0xf92ebdeab45d368f6354e8c5a8ac586c"]
    })"_json);
}

TEST_CASE("deserialize ExecutionPayloadV1", "[silkworm][rpc][json]") {
    ExecutionPayload payload = R"({
        "parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
        "feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
        "stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45",
        "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000001",
        "blockNumber":"0x1",
        "gasLimit":"0x1c9c380",
        "gasUsed":"0x0",
        "timestamp":"0x5",
        "extraData":"0x",
        "baseFeePerGas":"0x7",
        "blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
        "transactions":["0xf92ebdeab45d368f6354e8c5a8ac586c"]
    })"_json;
    CHECK(payload.version == ExecutionPayload::V1);
    CHECK(payload.parent_hash == 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32);
    CHECK(payload.suggested_fee_recipient == 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address);
    CHECK(payload.state_root == 0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45_bytes32);
    CHECK(payload.receipts_root == 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32);
    CHECK(payload.prev_randao == 0x0000000000000000000000000000000000000000000000000000000000000001_bytes32);
    CHECK(payload.number == 0x1);
    CHECK(payload.gas_limit == 0x1c9c380);
    CHECK(payload.timestamp == 0x5);
    CHECK(payload.base_fee == 0x7);
    CHECK(payload.block_hash == 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32);
    CHECK(payload.transactions == std::vector<Bytes>{{0xf9, 0x2e, 0xbd, 0xea, 0xb4, 0x5d, 0x36, 0x8f, 0x63, 0x54, 0xe8, 0xc5, 0xa8, 0xac, 0x58, 0x6c}});
    CHECK(payload.withdrawals == std::nullopt);
}

TEST_CASE("serialize ExecutionPayloadV2", "[silkworm][rpc][json]") {
    ExecutionPayload payload_v2{
        .version = ExecutionPayload::V2,
        .number = 0x1,
        .timestamp = 0x5,
        .gas_limit = 0x1c9c380,
        .suggested_fee_recipient = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address,
        .state_root = 0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45_bytes32,
        .receipts_root = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32,
        .parent_hash = 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32,
        .block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
        .prev_randao = 0x0000000000000000000000000000000000000000000000000000000000000001_bytes32,
        .base_fee = 0x7,
        .transactions = {*silkworm::from_hex("0xf92ebdeab45d368f6354e8c5a8ac586c")},
        .withdrawals = std::vector<Withdrawal>{},
    };
    SECTION("empty withdrawals") {
        CHECK(nlohmann::json(payload_v2) == R"({
            "parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
            "feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45",
            "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000001",
            "blockNumber":"0x1",
            "gasLimit":"0x1c9c380",
            "gasUsed":"0x0",
            "timestamp":"0x5",
            "extraData":"0x",
            "baseFeePerGas":"0x7",
            "blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
            "transactions":["0xf92ebdeab45d368f6354e8c5a8ac586c"],
            "withdrawals":[]
        })"_json);
    }
    SECTION("non-empty withdrawals") {
        payload_v2.withdrawals = std::vector<Withdrawal>{
            {.index = 6, .validator_index = 12, .address = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address, .amount = 10'000},
        };
        CHECK(nlohmann::json(payload_v2) == R"({
            "parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
            "feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45",
            "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000001",
            "blockNumber":"0x1",
            "gasLimit":"0x1c9c380",
            "gasUsed":"0x0",
            "timestamp":"0x5",
            "extraData":"0x",
            "baseFeePerGas":"0x7",
            "blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
            "transactions":["0xf92ebdeab45d368f6354e8c5a8ac586c"],
            "withdrawals":[{"address":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","amount":"0x2710","index":"0x6","validatorIndex":"0xc"}]
        })"_json);
    }
}

TEST_CASE("deserialize ExecutionPayloadV2", "[silkworm][rpc][json]") {
    SECTION("empty withdrawals") {
        ExecutionPayload payload = R"({
            "parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
            "feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45",
            "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000001",
            "blockNumber":"0x1",
            "gasLimit":"0x1c9c380",
            "gasUsed":"0x0",
            "timestamp":"0x5",
            "extraData":"0x",
            "baseFeePerGas":"0x7",
            "blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
            "transactions":["0xf92ebdeab45d368f6354e8c5a8ac586c"],
            "withdrawals":[]
        })"_json;
        CHECK(payload.version == ExecutionPayload::V2);
        CHECK(payload.parent_hash == 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32);
        CHECK(payload.suggested_fee_recipient == 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address);
        CHECK(payload.state_root == 0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45_bytes32);
        CHECK(payload.receipts_root == 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32);
        CHECK(payload.prev_randao == 0x0000000000000000000000000000000000000000000000000000000000000001_bytes32);
        CHECK(payload.number == 0x1);
        CHECK(payload.gas_limit == 0x1c9c380);
        CHECK(payload.timestamp == 0x5);
        CHECK(payload.base_fee == 0x7);
        CHECK(payload.block_hash == 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32);
        CHECK(payload.transactions == std::vector<Bytes>{{0xf9, 0x2e, 0xbd, 0xea, 0xb4, 0x5d, 0x36, 0x8f, 0x63, 0x54, 0xe8, 0xc5, 0xa8, 0xac, 0x58, 0x6c}});
        CHECK(payload.withdrawals == std::vector<Withdrawal>{});
    }
    SECTION("non-empty withdrawals") {
        ExecutionPayload payload = R"({
            "parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
            "feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45",
            "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000001",
            "blockNumber":"0x1",
            "gasLimit":"0x1c9c380",
            "gasUsed":"0x0",
            "timestamp":"0x5",
            "extraData":"0x",
            "baseFeePerGas":"0x7",
            "blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
            "transactions":["0xf92ebdeab45d368f6354e8c5a8ac586c"],
            "withdrawals":[{"address":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","amount":"0x2710","index":"0x6","validatorIndex":"0xc"}]
        })"_json;
        CHECK(payload.version == ExecutionPayload::V2);
        CHECK(payload.parent_hash == 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32);
        CHECK(payload.suggested_fee_recipient == 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address);
        CHECK(payload.state_root == 0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45_bytes32);
        CHECK(payload.receipts_root == 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32);
        CHECK(payload.prev_randao == 0x0000000000000000000000000000000000000000000000000000000000000001_bytes32);
        CHECK(payload.number == 0x1);
        CHECK(payload.gas_limit == 0x1c9c380);
        CHECK(payload.timestamp == 0x5);
        CHECK(payload.base_fee == 0x7);
        CHECK(payload.block_hash == 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32);
        CHECK(payload.transactions == std::vector<Bytes>{{0xf9, 0x2e, 0xbd, 0xea, 0xb4, 0x5d, 0x36, 0x8f, 0x63, 0x54, 0xe8, 0xc5, 0xa8, 0xac, 0x58, 0x6c}});
        CHECK(payload.withdrawals == std::vector<Withdrawal>{
                                         {.index = 6, .validator_index = 12, .address = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address, .amount = 10'000},
                                     });
    }
    SECTION("invalid hex transaction") {
        const auto json = R"({
            "parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
            "feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45",
            "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000001",
            "blockNumber":"0x1",
            "gasLimit":"0x1c9c380",
            "gasUsed":"0x0",
            "timestamp":"0x5",
            "extraData":"0x",
            "baseFeePerGas":"0x7",
            "blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
            "transactions":["xyz"],
            "withdrawals":[{"address":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","amount":"0x2710","index":"0x6","validatorIndex":"0xc"}]
        })"_json;
        ExecutionPayload payload;
        CHECK_THROWS_AS(from_json(json, payload), std::system_error);
    }
}

TEST_CASE("serialize ExecutionPayloadAndValue", "[silkworm][rpc][json]") {
    ExecutionPayload payload_v1{
        .version = ExecutionPayload::V1,
        .number = 0x1,
        .timestamp = 0x5,
        .gas_limit = 0x1c9c380,
        .suggested_fee_recipient = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address,
        .state_root = 0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45_bytes32,
        .receipts_root = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32,
        .parent_hash = 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32,
        .block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
        .prev_randao = 0x0000000000000000000000000000000000000000000000000000000000000001_bytes32,
        .base_fee = 0x7,
        .transactions = {*silkworm::from_hex("0xf92ebdeab45d368f6354e8c5a8ac586c")},
    };
    ExecutionPayloadAndValue payload_and_value{payload_v1, 4'000'000};
    CHECK(nlohmann::json(payload_and_value) == R"({
        "executionPayload":{
            "parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
            "feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45",
            "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000001",
            "blockNumber":"0x1",
            "gasLimit":"0x1c9c380",
            "gasUsed":"0x0",
            "timestamp":"0x5",
            "extraData":"0x",
            "baseFeePerGas":"0x7",
            "blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
            "transactions":["0xf92ebdeab45d368f6354e8c5a8ac586c"]
        },
        "blockValue":"0x3d0900"
    })"_json);
}

TEST_CASE("serialize ExecutionPayloadBody", "[silkworm][rpc][json]") {
    ExecutionPayloadBody payload_body{
        .transactions = std::vector<Bytes>{*silkworm::from_hex("0xf92ebdeab45d368f6354e8c5a8ac586c")},
        .withdrawals = std::vector<Withdrawal>{
            {.index = 6, .validator_index = 12, .address = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address, .amount = 10'000},
        }};
    CHECK(nlohmann::json(payload_body) == R"({
        "transactions":["0xf92ebdeab45d368f6354e8c5a8ac586c"],
        "withdrawals":[{"address":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","amount":"0x2710","index":"0x6","validatorIndex":"0xc"}]
    })"_json);
}

}  // namespace silkworm::rpc
