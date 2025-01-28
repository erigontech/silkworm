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

#include "sync_pos.hpp"

#include <array>

#include <catch2/catch_test_macros.hpp>
#include <gmock/gmock.h>

#include <silkworm/infra/concurrency/sleep.hpp>
#include <silkworm/rpc/test_util/service_context_test_base.hpp>

#include "test_util/mock_block_exchange.hpp"
#include "test_util/mock_execution_client.hpp"

namespace silkworm::chainsync {

using namespace std::chrono_literals;
using testing::_;
using testing::InvokeWithoutArgs;

using namespace execution::api;

class PoSSyncTest : public rpc::test_util::ServiceContextTestBase {
  public:
    std::unique_ptr<test_util::MockBlockExchange> block_exchange{make_block_exchange()};
    std::shared_ptr<test_util::MockExecutionService> execution_service{std::make_shared<test_util::MockExecutionService>()};
    test_util::MockExecutionClient execution_client{execution_service};

  protected:
    PoSSync sync_{*block_exchange, execution_client};

    static std::unique_ptr<test_util::MockBlockExchange> make_block_exchange() {
        auto block_exchange = std::make_unique<test_util::MockBlockExchange>();
        EXPECT_CALL(*block_exchange, chain_config)
            .WillRepeatedly([]() -> const ChainConfig& { return kSepoliaConfig; });
        return block_exchange;
    }
};

static rpc::NewPayloadRequest make_fixed_payload_request(rpc::ExecutionPayload::Version version) {
    return {
        .execution_payload = rpc::ExecutionPayload{
            .version = version,
            .block_num = 1,
            .timestamp = 0x05,
            .gas_limit = 0x1c9c380,
            .gas_used = 0x0,
            .suggested_fee_recipient = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address,
            .state_root = 0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45_bytes32,
            .receipts_root = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32,
            .parent_hash = 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32,
            .block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
            .prev_randao = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32,
            .base_fee = 0x7,
        }};
}

static rpc::NewPayloadRequest make_payload_request_v3() {
    Transaction txn{};
    txn.type = TransactionType::kBlob;
    txn.chain_id = 5;
    txn.nonce = 7;
    txn.max_priority_fee_per_gas = 10000000000;
    txn.max_fee_per_gas = 30000000000;
    txn.gas_limit = 5748100;
    txn.to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address;
    txn.data = *from_hex("04f7");
    txn.access_list = std::vector<AccessListEntry>{
        {0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae_address,
         {
             0x0000000000000000000000000000000000000000000000000000000000000003_bytes32,
             0x0000000000000000000000000000000000000000000000000000000000000007_bytes32,
         }},
        {0xbb9bc244d798123fde783fcc1c72d3bb8c189413_address, {}},
    };
    txn.max_fee_per_blob_gas = 123;
    txn.blob_versioned_hashes = {
        0xc6bdd1de713471bd6cfa62dd8b5a5b42969ed09e26212d3377f3f8426d8ec210_bytes32,
        0x8aaeccaf3873d07cef005aca28c39f8a9f8bdb1ec8d79ffc25afc0a4fa2ab736_bytes32,
    };
    txn.odd_y_parity = true;
    txn.r = intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0");
    txn.s = intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094");
    Bytes encoded_txn{};
    rlp::encode(encoded_txn, txn);

    rpc::NewPayloadRequest request{make_fixed_payload_request(rpc::ExecutionPayload::kV3)};
    request.execution_payload.block_hash = 0x56702ce3c31f2f4b57edcfaea96bb8dd4a6332ca79e5fd1012821585b005d5d7_bytes32;
    request.execution_payload.blob_gas_used = 0x100;
    request.execution_payload.excess_blob_gas = 0x10;
    request.execution_payload.transactions.emplace_back(std::move(encoded_txn));
    request.expected_blob_versioned_hashes = {
        0xc6bdd1de713471bd6cfa62dd8b5a5b42969ed09e26212d3377f3f8426d8ec210_bytes32,
        0x8aaeccaf3873d07cef005aca28c39f8a9f8bdb1ec8d79ffc25afc0a4fa2ab736_bytes32,
    };
    return request;
}

static const std::array kNewPayloadRequests{
    make_fixed_payload_request(rpc::ExecutionPayload::kV1),
    make_fixed_payload_request(rpc::ExecutionPayload::kV2),
    make_fixed_payload_request(rpc::ExecutionPayload::kV3),
    make_payload_request_v3(),
};

TEST_CASE_METHOD(PoSSyncTest, "PoSSync::new_payload.get_header_timeout", "[sync]") {
    for (size_t i{0}; i < kNewPayloadRequests.size(); ++i) {
        const auto& request{kNewPayloadRequests[i]};
        const auto& payload{request.execution_payload};
        SECTION("payload version: v" + std::to_string(payload.version) + " i=" + std::to_string(i)) {
            EXPECT_CALL(*execution_service, get_header(BlockNumOrHash{payload.parent_hash}))
                .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<BlockHeader>> {
                    co_await sleep(1h);  // simulate exaggeratedly long-running task
                    co_return BlockHeader{};
                }));

            CHECK(spawn_and_wait(sync_.new_payload(request, 1ms)).status == rpc::PayloadStatus::kSyncingStr);
        }
    }
}

TEST_CASE_METHOD(PoSSyncTest, "PoSSync::new_payload.get_td_timeout", "[sync]") {
    for (size_t i{0}; i < kNewPayloadRequests.size(); ++i) {
        const auto& request{kNewPayloadRequests[i]};
        const auto& payload{request.execution_payload};
        const execution::api::BlockNumOrHash parent_block_num_or_hash{payload.parent_hash};
        SECTION("payload version: v" + std::to_string(payload.version) + " i=" + std::to_string(i)) {
            EXPECT_CALL(*execution_service, get_header(parent_block_num_or_hash))
                .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<BlockHeader>> {
                    co_return BlockHeader{};
                }));
            EXPECT_CALL(*execution_service, get_td(parent_block_num_or_hash))
                .WillOnce(InvokeWithoutArgs([&]() -> Task<std::optional<TotalDifficulty>> {
                    co_await sleep(1h);  // simulate exaggeratedly long-running task
                    co_return kSepoliaConfig.terminal_total_difficulty;
                }));

            CHECK(spawn_and_wait(sync_.new_payload(request, 1ms)).status == rpc::PayloadStatus::kSyncingStr);
        }
    }
}

TEST_CASE_METHOD(PoSSyncTest, "PoSSync::new_payload.insert_blocks_timeout", "[sync]") {
    for (size_t i{0}; i < kNewPayloadRequests.size(); ++i) {
        const auto& request{kNewPayloadRequests[i]};
        const auto& payload{request.execution_payload};
        const execution::api::BlockNumOrHash parent_block_num_or_hash{payload.parent_hash};
        SECTION("payload version: v" + std::to_string(payload.version) + " i=" + std::to_string(i)) {
            EXPECT_CALL(*execution_service, get_header(parent_block_num_or_hash))
                .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<BlockHeader>> {
                    co_return BlockHeader{};
                }));
            EXPECT_CALL(*execution_service, get_td(parent_block_num_or_hash))
                .WillOnce(InvokeWithoutArgs([&]() -> Task<std::optional<TotalDifficulty>> {
                    co_return kSepoliaConfig.terminal_total_difficulty;
                }));
            EXPECT_CALL(*execution_service, insert_blocks(_))
                .WillOnce(InvokeWithoutArgs([]() -> Task<execution::api::InsertionResult> {
                    co_await sleep(1h);  // simulate exaggeratedly long-running task
                    co_return execution::api::InsertionResult{};
                }));

            CHECK(spawn_and_wait(sync_.new_payload(request, 1ms)).status == rpc::PayloadStatus::kSyncingStr);
        }
    }
}

TEST_CASE_METHOD(PoSSyncTest, "PoSSync::new_payload.get_header_hash_number_timeout", "[sync]") {
    for (size_t i{0}; i < kNewPayloadRequests.size(); ++i) {
        const auto& request{kNewPayloadRequests[i]};
        const auto& payload{request.execution_payload};
        const execution::api::BlockNumOrHash parent_block_num_or_hash{payload.parent_hash};
        SECTION("payload version: v" + std::to_string(payload.version) + " i=" + std::to_string(i)) {
            EXPECT_CALL(*execution_service, get_header(parent_block_num_or_hash))
                .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<BlockHeader>> {
                    co_return BlockHeader{};
                }));
            EXPECT_CALL(*execution_service, get_td(parent_block_num_or_hash))
                .WillOnce(InvokeWithoutArgs([&]() -> Task<std::optional<TotalDifficulty>> {
                    co_return kSepoliaConfig.terminal_total_difficulty;
                }));
            EXPECT_CALL(*execution_service, insert_blocks(_))
                .WillOnce(InvokeWithoutArgs([]() -> Task<execution::api::InsertionResult> {
                    co_return execution::api::InsertionResult{};
                }));
            EXPECT_CALL(*execution_service, get_header_hash_number(Hash{payload.block_hash}))
                .WillOnce(InvokeWithoutArgs([=]() -> Task<std::optional<BlockNum>> {
                    co_await sleep(1h);  // simulate exaggeratedly long-running task
                    co_return payload.block_num;
                }));

            CHECK(spawn_and_wait(sync_.new_payload(request, 1ms)).status == rpc::PayloadStatus::kSyncingStr);
        }
    }
}

TEST_CASE_METHOD(PoSSyncTest, "PoSSync::new_payload.validate_chain_timeout", "[sync]") {
    for (size_t i{0}; i < kNewPayloadRequests.size(); ++i) {
        const auto& request{kNewPayloadRequests[i]};
        const auto& payload{request.execution_payload};
        const BlockId block_num_or_hash{payload.block_num, payload.block_hash};
        const execution::api::BlockNumOrHash parent_block_num_or_hash{payload.parent_hash};
        SECTION("payload version: v" + std::to_string(payload.version) + " i=" + std::to_string(i)) {
            EXPECT_CALL(*execution_service, get_header(parent_block_num_or_hash))
                .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<BlockHeader>> {
                    co_return BlockHeader{};
                }));
            EXPECT_CALL(*execution_service, get_td(parent_block_num_or_hash))
                .WillOnce(InvokeWithoutArgs([&]() -> Task<std::optional<TotalDifficulty>> {
                    co_return kSepoliaConfig.terminal_total_difficulty;
                }));
            EXPECT_CALL(*execution_service, insert_blocks(_))
                .WillOnce(InvokeWithoutArgs([]() -> Task<execution::api::InsertionResult> { co_return execution::api::InsertionResult{}; }));
            EXPECT_CALL(*execution_service, get_header_hash_number(Hash{payload.block_hash}))
                .WillOnce(InvokeWithoutArgs([=]() -> Task<std::optional<BlockNum>> { co_return payload.block_num; }));
            EXPECT_CALL(*execution_service, validate_chain(block_num_or_hash))
                .WillOnce(InvokeWithoutArgs([&]() -> Task<execution::api::ValidationResult> {
                    co_await sleep(1h);  // simulate exaggeratedly long-running task
                    co_return execution::api::ValidChain{};
                }));

            CHECK(spawn_and_wait(sync_.new_payload(request, 1ms)).status == rpc::PayloadStatus::kSyncingStr);
        }
    }
}

TEST_CASE_METHOD(PoSSyncTest, "PoSSync::new_payload.validate_chain_success", "[sync]") {
    for (size_t i{0}; i < kNewPayloadRequests.size(); ++i) {
        const auto& request{kNewPayloadRequests[i]};
        const auto& payload{request.execution_payload};
        const BlockId block_num_or_hash{payload.block_num, payload.block_hash};
        const execution::api::BlockNumOrHash parent_block_num_or_hash{payload.parent_hash};
        SECTION("payload version: v" + std::to_string(payload.version) + " i=" + std::to_string(i)) {
            EXPECT_CALL(*execution_service, get_header(parent_block_num_or_hash))
                .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<BlockHeader>> {
                    co_return BlockHeader{};
                }));
            EXPECT_CALL(*execution_service, get_td(parent_block_num_or_hash))
                .WillOnce(InvokeWithoutArgs([&]() -> Task<std::optional<TotalDifficulty>> {
                    co_return kSepoliaConfig.terminal_total_difficulty;
                }));
            EXPECT_CALL(*execution_service, insert_blocks(_))
                .WillOnce(InvokeWithoutArgs([]() -> Task<execution::api::InsertionResult> { co_return execution::api::InsertionResult{}; }));
            EXPECT_CALL(*execution_service, get_header_hash_number(Hash{payload.block_hash}))
                .WillOnce(InvokeWithoutArgs([=]() -> Task<std::optional<BlockNum>> { co_return payload.block_num; }));
            EXPECT_CALL(*execution_service, validate_chain(block_num_or_hash))
                .WillOnce(InvokeWithoutArgs([&]() -> Task<execution::api::ValidationResult> {
                    co_return execution::api::ValidChain{};
                }));

            CHECK(spawn_and_wait(sync_.new_payload(request, 1ms)).status == rpc::PayloadStatus::kValidStr);
        }
    }
}

static const rpc::ForkChoiceUpdatedRequest kInvalidForkChoiceUpdatedRequest{
    .fork_choice_state = rpc::ForkChoiceState{
        .head_block_hash = kZeroHash,
        .safe_block_hash = kZeroHash,
        .finalized_block_hash = kZeroHash,
    },
};

TEST_CASE_METHOD(PoSSyncTest, "PoSSync::fork_choice_updated.invalid_request", "[sync]") {
    const auto request = kInvalidForkChoiceUpdatedRequest;
    CHECK(spawn_and_wait(sync_.fork_choice_updated(request, 1ms)).payload_status.status == rpc::PayloadStatus::kInvalidStr);
}

static const rpc::ForkChoiceUpdatedRequest kValidForkChoiceUpdatedRequest{
    .fork_choice_state = rpc::ForkChoiceState{
        .head_block_hash = 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32,
        .safe_block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
        .finalized_block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
    },
};

TEST_CASE_METHOD(PoSSyncTest, "PoSSync::fork_choice_updated.get_header1_timeout", "[sync]") {
    const auto request = kValidForkChoiceUpdatedRequest;
    const auto& fork_choice_state{request.fork_choice_state};
    const execution::api::BlockNumOrHash head_block_hash{fork_choice_state.head_block_hash};
    EXPECT_CALL(*execution_service, get_header(head_block_hash))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<BlockHeader>> {
            co_await sleep(1h);  // simulate exaggeratedly long-running task
            co_return BlockHeader{};
        }));

    CHECK(spawn_and_wait(sync_.fork_choice_updated(request, 1ms)).payload_status.status == rpc::PayloadStatus::kSyncingStr);
}

TEST_CASE_METHOD(PoSSyncTest, "PoSSync::fork_choice_updated.get_header2_timeout", "[sync]") {
    const auto request = kValidForkChoiceUpdatedRequest;
    const auto& fork_choice_state{request.fork_choice_state};
    const execution::api::BlockNumOrHash head_block_hash{fork_choice_state.head_block_hash};
    const auto head_parent_hash = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;
    EXPECT_CALL(*execution_service, get_header(head_block_hash))
        .WillOnce(InvokeWithoutArgs([&]() -> Task<std::optional<BlockHeader>> {
            co_return BlockHeader{.parent_hash = head_parent_hash};
        }));
    const execution::api::BlockNumOrHash head_parent_block_num_or_hash{head_parent_hash};
    EXPECT_CALL(*execution_service, get_header(head_parent_block_num_or_hash))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<BlockHeader>> {
            co_await sleep(1h);  // simulate exaggeratedly long-running task
            co_return BlockHeader{};
        }));

    CHECK(spawn_and_wait(sync_.fork_choice_updated(request, 1ms)).payload_status.status == rpc::PayloadStatus::kSyncingStr);
}

}  // namespace silkworm::chainsync
