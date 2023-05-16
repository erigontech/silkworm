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

#include <silkworm/silkrpc/json/types.hpp>

namespace silkworm::rpc {

using Catch::Matchers::Message;
using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

TEST_CASE("serialize execution_payload", "[silkworm::json][to_json]") {
    // uint64_t are kept as hex for readability
    silkworm::rpc::ExecutionPayload execution_payload{
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
    nlohmann::json j = execution_payload;
    CHECK(j == R"({
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

TEST_CASE("deserialize execution_payload", "[silkworm::json][to_json]") {
    // uint64_t are kept as hex for readability
    ExecutionPayload actual_payload = R"({
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
    // expected deserialization result
    ExecutionPayload expected_payload{
        .number = 0x1,
        .timestamp = 0x5,
        .gas_limit = 0x1c9c380,
        .gas_used = 0x0,
        .suggested_fee_recipient = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address,
        .state_root = 0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45_bytes32,
        .receipts_root = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32,
        .parent_hash = 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32,
        .block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
        .prev_randao = 0x0000000000000000000000000000000000000000000000000000000000000001_bytes32,
        .base_fee = 0x7,
        .transactions = {{0xf9, 0x2e, 0xbd, 0xea, 0xb4, 0x5d, 0x36, 0x8f, 0x63, 0x54, 0xe8, 0xc5, 0xa8, 0xac, 0x58, 0x6c}},
    };

    CHECK(actual_payload.parent_hash == expected_payload.parent_hash);
    CHECK(actual_payload.suggested_fee_recipient == expected_payload.suggested_fee_recipient);
    CHECK(actual_payload.state_root == expected_payload.state_root);
    CHECK(actual_payload.receipts_root == expected_payload.receipts_root);
    CHECK(actual_payload.prev_randao == expected_payload.prev_randao);
    CHECK(actual_payload.number == expected_payload.number);
    CHECK(actual_payload.gas_limit == expected_payload.gas_limit);
    CHECK(actual_payload.timestamp == expected_payload.timestamp);
    CHECK(actual_payload.base_fee == expected_payload.base_fee);
    CHECK(actual_payload.block_hash == expected_payload.block_hash);
    CHECK(actual_payload.transactions == expected_payload.transactions);
}

}  // namespace silkworm::rpc
