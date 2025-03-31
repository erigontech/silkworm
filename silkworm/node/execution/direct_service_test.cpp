// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdexcept>
#include <utility>

#include <catch2/catch_test_macros.hpp>
#include <gmock/gmock.h>

#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/execution/api/direct_service.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/infra/test_util/task_runner.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>
#include <silkworm/node/test_util/mock_execution_engine.hpp>
#include <silkworm/node/test_util/temp_chain_data_node_settings.hpp>

namespace silkworm::execution::api {

using testing::InvokeWithoutArgs;

using silkworm::db::test_util::TempChainData;
using silkworm::node::test_util::make_node_settings_from_temp_chain_data;
using silkworm::test_util::TaskRunner;

struct DirectServiceTest : public TaskRunner {
    explicit DirectServiceTest()
        : settings{make_node_settings_from_temp_chain_data(tmp_chaindata)} {
        tmp_chaindata.add_genesis_data();
        tmp_chaindata.commit_txn();
        mock_execution_engine = std::make_unique<MockExecutionEngine>(executor(), settings, tmp_chaindata.chaindata_rw());
        direct_service = std::make_unique<DirectService>(*mock_execution_engine);
    }

    TempChainData tmp_chaindata;
    NodeSettings settings;
    std::unique_ptr<MockExecutionEngine> mock_execution_engine;
    std::unique_ptr<DirectService> direct_service;
};

TEST_CASE_METHOD(DirectServiceTest, "DirectService::insert_blocks", "[node][execution][api]") {
    const std::vector<Blocks> test_vectors = {
        Blocks{},
        Blocks{std::make_shared<Block>()},
    };
    for (const auto& blocks : test_vectors) {
        SECTION("blocks: " + std::to_string(blocks.size())) {
            EXPECT_CALL(*mock_execution_engine, insert_blocks(blocks))
                .WillOnce(InvokeWithoutArgs([]() -> void {
                    return;
                }));
            auto future = spawn_future(direct_service->insert_blocks(blocks));
            ioc().run();
            CHECK(future.get().status == api::ExecutionStatus::kSuccess);
        }
    }
}

TEST_CASE_METHOD(DirectServiceTest, "DirectService::verify_chain", "[node][execution][api]") {
    const Hash latest_valid_hash{0x000000000000000000000000000000000000000000000000000000000000000A_bytes32};
    const Hash new_hash{0x000000000000000000000000000000000000000000000000000000000000000B_bytes32};
    const BlockId latest_valid_head{
        .block_num = 1,
        .hash = latest_valid_hash,
    };
    const BlockId new_head{
        .block_num = 2,
        .hash = new_hash,
    };
    const std::vector<std::pair<VerificationResult, execution::api::ValidationResult>> test_vectors{
        {ValidChain{.current_head = new_head}, api::ValidChain{.current_head = new_head}},
        {InvalidChain{.unwind_point = latest_valid_head}, api::InvalidChain{.unwind_point = latest_valid_head}},
        {ValidationError{.latest_valid_head = latest_valid_head}, api::ValidationError{.latest_valid_head = latest_valid_head}},
    };
    for (const auto& [stagedsync_result, api_result] : test_vectors) {
        SECTION("result: " + std::to_string(stagedsync_result.index())) {
            EXPECT_CALL(*mock_execution_engine, verify_chain(new_head.hash))
                .WillOnce(InvokeWithoutArgs([result = stagedsync_result]() -> Task<VerificationResult> {
                    co_return result;
                }));
            auto future = spawn_future(direct_service->validate_chain(new_head));
            ioc().run();
            const auto result{future.get()};
            if (std::holds_alternative<ValidChain>(stagedsync_result)) {
                CHECK(std::holds_alternative<api::ValidChain>(result));
                const auto stagedsync_valid_chain{std::get<ValidChain>(stagedsync_result)};
                const auto api_valid_chain{std::get<api::ValidChain>(result)};
                CHECK(stagedsync_valid_chain.current_head == api_valid_chain.current_head);
            } else if (std::holds_alternative<InvalidChain>(stagedsync_result)) {
                CHECK(std::holds_alternative<api::InvalidChain>(result));
                const auto stagedsync_invalid_chain{std::get<InvalidChain>(stagedsync_result)};
                const auto api_invalid_chain{std::get<api::InvalidChain>(result)};
                CHECK(stagedsync_invalid_chain.unwind_point == api_invalid_chain.unwind_point);
                CHECK(stagedsync_invalid_chain.bad_headers == api_invalid_chain.bad_headers);
                CHECK(stagedsync_invalid_chain.bad_block == api_invalid_chain.bad_block);
            } else if (std::holds_alternative<ValidationError>(stagedsync_result)) {
                CHECK(std::holds_alternative<api::ValidationError>(result));
                const auto stagedsync_error{std::get<ValidationError>(stagedsync_result)};
                const auto api_error{std::get<api::ValidationError>(result)};
                CHECK(stagedsync_error.latest_valid_head == api_error.latest_valid_head);
            } else {
                REQUIRE(false);
            }
        }
    }
}

TEST_CASE_METHOD(DirectServiceTest, "DirectService::update_fork_choice", "[node][execution][api]") {
    const Hash head_block_hash{0x000000000000000000000000000000000000000000000000000000000000000A_bytes32};
    const Hash finalized_block_hash{0x0000000000000000000000000000000000000000000000000000000000000002_bytes32};
    const Hash safe_block_hash{0x0000000000000000000000000000000000000000000000000000000000000001_bytes32};
    const ForkChoice fork_choice{
        .head_block_hash = head_block_hash,
        .timeout = 0,
        .finalized_block_hash = finalized_block_hash,
        .safe_block_hash = safe_block_hash,
    };
    const std::vector<std::pair<bool, ForkChoiceResult>> test_vectors{
        {true, ForkChoiceResult{.status = api::ExecutionStatus::kSuccess, .latest_valid_head = head_block_hash}},
        {false, ForkChoiceResult{.status = api::ExecutionStatus::kInvalidForkchoice, .latest_valid_head = finalized_block_hash}},
    };
    for (const auto& [updated, expected_choice_result] : test_vectors) {
        SECTION("updated: " + std::to_string(updated)) {
            EXPECT_CALL(*mock_execution_engine, notify_fork_choice_update3(head_block_hash, finalized_block_hash, safe_block_hash))
                .WillOnce(InvokeWithoutArgs([result = updated]() -> bool {
                    return result;
                }));
            EXPECT_CALL(*mock_execution_engine, last_fork_choice())
                .WillOnce(InvokeWithoutArgs([=, result = updated]() -> BlockId {
                    return result ? BlockId{10, head_block_hash} : BlockId{2, finalized_block_hash};
                }));
            auto future = spawn_future(direct_service->update_fork_choice(fork_choice));
            ioc().run();
            const auto fork_choice_result{future.get()};
            CHECK(fork_choice_result.status == expected_choice_result.status);
            CHECK(fork_choice_result.latest_valid_head == expected_choice_result.latest_valid_head);
        }
    }
}

TEST_CASE_METHOD(DirectServiceTest, "DirectService::get_block_num", "[node][execution][api]") {
    const Hash block_hash{0x000000000000000000000000000000000000000000000000000000000000000A_bytes32};
    SECTION("non-existent") {
        EXPECT_CALL(*mock_execution_engine, get_block_num(block_hash))
            .WillOnce(InvokeWithoutArgs([=]() -> std::optional<BlockNum> {
                return {};
            }));
        auto future = spawn_future(direct_service->get_header_hash_number(block_hash));
        ioc().run();
        CHECK(future.get() == std::nullopt);
    }
    SECTION("existent") {
        const BlockNum block_num{2};
        EXPECT_CALL(*mock_execution_engine, get_block_num(block_hash))
            .WillOnce(InvokeWithoutArgs([=]() -> std::optional<BlockNum> {
                return block_num;
            }));
        auto future = spawn_future(direct_service->get_header_hash_number(block_hash));
        ioc().run();
        CHECK(future.get() == block_num);
    }
}

TEST_CASE_METHOD(DirectServiceTest, "DirectService::get_fork_choice", "[node][execution][api]") {
    const Hash head_block_hash{0x000000000000000000000000000000000000000000000000000000000000000A_bytes32};
    const Hash finalized_block_hash{0x0000000000000000000000000000000000000000000000000000000000000002_bytes32};
    const Hash safe_block_hash{0x0000000000000000000000000000000000000000000000000000000000000001_bytes32};
    const ForkChoice expected_fork_choice{
        .head_block_hash = head_block_hash,
        .timeout = 0,
        .finalized_block_hash = finalized_block_hash,
        .safe_block_hash = safe_block_hash,
    };
    EXPECT_CALL(*mock_execution_engine, last_fork_choice())
        .WillOnce(InvokeWithoutArgs([=]() -> BlockId {
            return {10, head_block_hash};
        }));
    EXPECT_CALL(*mock_execution_engine, last_finalized_block())
        .WillOnce(InvokeWithoutArgs([=]() -> BlockId {
            return {2, finalized_block_hash};
        }));
    EXPECT_CALL(*mock_execution_engine, last_safe_block())
        .WillOnce(InvokeWithoutArgs([=]() -> BlockId {
            return {1, safe_block_hash};
        }));
    auto future = spawn_future(direct_service->get_fork_choice());
    ioc().run();
    const auto last_choice{future.get()};
    CHECK(last_choice.head_block_hash == expected_fork_choice.head_block_hash);
    CHECK(last_choice.timeout == expected_fork_choice.timeout);
    CHECK(last_choice.finalized_block_hash == expected_fork_choice.finalized_block_hash);
    CHECK(last_choice.safe_block_hash == expected_fork_choice.safe_block_hash);
}

TEST_CASE_METHOD(DirectServiceTest, "DirectService::get_last_headers", "[node][execution][api]") {
    const std::vector<std::pair<uint64_t, BlockHeaders>> test_vectors = {
        {0, {}},
        {1, {BlockHeader{}}},
    };
    for (const auto& [how_many, last_headers] : test_vectors) {
        SECTION("how_many: " + std::to_string(how_many)) {
            EXPECT_CALL(*mock_execution_engine, get_last_headers(how_many))
                .WillOnce(InvokeWithoutArgs([&, headers = last_headers]() -> BlockHeaders {
                    return headers;
                }));
            auto future = spawn_future(direct_service->get_last_headers(how_many));
            ioc().run();
            CHECK(future.get() == last_headers);
        }
    }
}

TEST_CASE_METHOD(DirectServiceTest, "DirectService::block_progress", "[node][execution][api]") {
    const BlockNum progress{123'456'789};
    EXPECT_CALL(*mock_execution_engine, block_progress())
        .WillOnce(InvokeWithoutArgs([=]() -> BlockNum {
            return progress;
        }));
    auto future = spawn_future(direct_service->block_progress());
    ioc().run();
    CHECK(future.get() == progress);
}

}  // namespace silkworm::execution::api
