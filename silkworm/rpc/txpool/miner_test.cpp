// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "miner.hpp"

#include <string>
#include <utility>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/infra/grpc/client/call.hpp>
#include <silkworm/infra/grpc/test_util/grpc_actions.hpp>
#include <silkworm/infra/grpc/test_util/grpc_responder.hpp>
#include <silkworm/infra/grpc/test_util/interfaces/mining_mock_fix24351.grpc.pb.h>
#include <silkworm/rpc/test_util/api_test_base.hpp>

namespace silkworm::rpc::txpool {

using evmc::literals::operator""_bytes32;
using StrictMockMiningStub = testing::StrictMock<::txpool::MockMiningStub>;

using MinerTest = test_util::GrpcApiTestBase<Miner, StrictMockMiningStub>;

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(MinerTest, "Miner::get_work", "[rpc][txpool][miner]") {
    test::StrictMockAsyncResponseReader<::txpool::GetWorkReply> reader;
    EXPECT_CALL(*stub_, AsyncGetWorkRaw).WillOnce(testing::Return(&reader));

    SECTION("call get_work and get result") {
        ::txpool::GetWorkReply response;
        response.set_header_hash("0x209f062567c161c5f71b3f57a7de277b0e95c3455050b152d785ad7524ef8ee7");
        response.set_seed_hash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");
        response.set_target("0xe7536c5b61ed0e0ab7f3ce7f085806d40f716689c0c086676757de401b595658");
        response.set_block_number("0x00000000");
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto work_result = run<&Miner::get_work>();
        CHECK(work_result.header_hash == 0x209f062567c161c5f71b3f57a7de277b0e95c3455050b152d785ad7524ef8ee7_bytes32);
        CHECK(work_result.seed_hash == 0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347_bytes32);
        CHECK(work_result.target == 0xe7536c5b61ed0e0ab7f3ce7f085806d40f716689c0c086676757de401b595658_bytes32);
        CHECK(work_result.block_num == *from_hex("0x00000000"));
    }

    SECTION("call get_work and get empty result") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto work = run<&Miner::get_work>();
        CHECK(!work.header_hash);
        CHECK(!work.seed_hash);
        CHECK(!work.target);
        CHECK(work.block_num == *from_hex("0x"));
    }

    SECTION("call get_work and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&Miner::get_work>()), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(MinerTest, "Miner::get_hashrate", "[rpc][txpool][miner]") {
    test::StrictMockAsyncResponseReader<::txpool::HashRateReply> reader;
    EXPECT_CALL(*stub_, AsyncHashRateRaw).WillOnce(testing::Return(&reader));

    SECTION("call get_hashrate and get result") {
        ::txpool::HashRateReply response;
        response.set_hash_rate(1234567);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto hash_rate = run<&Miner::get_hash_rate>();
        CHECK(hash_rate == 1234567);
    }

    SECTION("call get_hashrate and get empty result") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto hash_rate = run<&Miner::get_hash_rate>();
        CHECK(hash_rate == 0);
    }

    SECTION("call get_hashrate and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&Miner::get_hash_rate>()), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(MinerTest, "Miner::get_mining", "[rpc][txpool][miner]") {
    test::StrictMockAsyncResponseReader<::txpool::MiningReply> reader;
    EXPECT_CALL(*stub_, AsyncMiningRaw).WillOnce(testing::Return(&reader));

    const std::pair<bool, bool> enabled_running_pairs[] = {
        {false, false},
        {false, true},
        {true, false},
        {true, true},
    };
    for (const auto& [enabled, running] : enabled_running_pairs) {
        SECTION(std::string("call get_mining and get [") + std::to_string(enabled) + "," + std::to_string(running) + std::string("] result")) {
            ::txpool::MiningReply response;
            response.set_enabled(true);
            response.set_running(true);
            EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
            const auto mining = run<&Miner::get_mining>();
            CHECK(mining.enabled);
            CHECK(mining.running);
        }
    }

    SECTION("call get_mining and get empty result") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto mining = run<&Miner::get_mining>();
        CHECK(!mining.enabled);
        CHECK(!mining.running);
    }

    SECTION("call get_mining and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&Miner::get_mining>()), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(MinerTest, "Miner::submit_work", "[rpc][txpool][miner]") {
    test::StrictMockAsyncResponseReader<::txpool::SubmitWorkReply> reader;
    EXPECT_CALL(*stub_, AsyncSubmitWorkRaw).WillOnce(testing::Return(&reader));

    SECTION("call submit_work and get result") {
        ::txpool::SubmitWorkReply response;
        response.set_ok(true);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        Bytes block_nonce{};                 // don't care
        evmc::bytes32 pow_hash{kEmptyHash};  // don't care
        evmc::bytes32 digest{kEmptyHash};    // don't care
        const auto ok = run<&Miner::submit_work>(block_nonce, pow_hash, digest);
        CHECK(ok);
    }

    SECTION("call submit_work and get empty result") {
        Bytes block_nonce{};                 // don't care
        evmc::bytes32 pow_hash{kEmptyHash};  // don't care
        evmc::bytes32 digest{kEmptyHash};    // don't care
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto ok = run<&Miner::submit_work>(block_nonce, pow_hash, digest);
        CHECK(!ok);
    }

    SECTION("call submit_work and get error") {
        Bytes block_nonce{};                 // don't care
        evmc::bytes32 pow_hash{kEmptyHash};  // don't care
        evmc::bytes32 digest{kEmptyHash};    // don't care
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&Miner::submit_work>(block_nonce, pow_hash, digest)), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(MinerTest, "Miner::submit_hash_rate", "[rpc][txpool][miner]") {
    test::StrictMockAsyncResponseReader<::txpool::SubmitHashRateReply> reader;
    EXPECT_CALL(*stub_, AsyncSubmitHashRateRaw).WillOnce(testing::Return(&reader));

    SECTION("call submit_hash_rate and get result") {
        ::txpool::SubmitHashRateReply response;
        response.set_ok(true);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        intx::uint256 rate{};          // don't care
        evmc::bytes32 id{kEmptyHash};  // don't care
        const auto ok = run<&Miner::submit_hash_rate>(rate, id);
        CHECK(ok);
    }

    SECTION("call submit_hash_rate and get empty result") {
        intx::uint256 rate{};          // don't care
        evmc::bytes32 id{kEmptyHash};  // don't care
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto ok = run<&Miner::submit_hash_rate>(rate, id);
        CHECK(!ok);
    }

    SECTION("call submit_hash_rate and get error") {
        intx::uint256 rate{};          // don't care
        evmc::bytes32 id{kEmptyHash};  // don't care
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&Miner::submit_hash_rate>(rate, id)), rpc::GrpcStatusError);
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::txpool
