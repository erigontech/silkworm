// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "checkers.hpp"

#include <optional>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/infra/test_util/fixture.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../test_util/sample_protos.hpp"

namespace silkworm::execution::grpc::client {

using namespace evmc::literals;
using namespace silkworm::execution::test_util;
using namespace silkworm::test_util;
namespace proto = ::execution;

static proto::GetHeaderHashNumberResponse sample_response() {
    proto::GetHeaderHashNumberResponse response;
    response.set_block_number(kSampleBlockNum);
    return response;
}

TEST_CASE("block_num_from_response", "[node][execution][grpc]") {
    const Fixtures<proto::GetHeaderHashNumberResponse, std::optional<BlockNum>> fixtures{
        {{}, std::nullopt},
        {sample_response(), kSampleBlockNum},
    };
    for (const auto& [response, expected_block_num] : fixtures) {
        SECTION("response: " + std::to_string(response.block_number())) {
            CHECK(block_num_from_response(response) == expected_block_num);
        }
    }
}

static constexpr evmc::bytes32 kHeadHash{0x0000000000000000000000000000000000000000000000000000000000000001_bytes32};
static constexpr evmc::bytes32 kFinalizedHash{0x0000000000000000000000000000000000000000000000000000000000000002_bytes32};
static constexpr evmc::bytes32 kSafeHash{0x0000000000000000000000000000000000000000000000000000000000000003_bytes32};
static constexpr uint64_t kTimeout{100u};

static proto::ForkChoice sample_proto_fork_choice() {
    proto::ForkChoice fork_choice;
    fork_choice.set_allocated_head_block_hash(rpc::h256_from_bytes32(kHeadHash).release());
    fork_choice.set_timeout(kTimeout);
    fork_choice.set_allocated_finalized_block_hash(rpc::h256_from_bytes32(kFinalizedHash).release());
    fork_choice.set_allocated_safe_block_hash(rpc::h256_from_bytes32(kSafeHash).release());
    return fork_choice;
}

static api::ForkChoice sample_fork_choice() {
    api::ForkChoice fork_choice{
        .head_block_hash = kHeadHash,
        .timeout = kTimeout,
        .finalized_block_hash = kFinalizedHash,
        .safe_block_hash = kSafeHash,
    };

    return fork_choice;
}

TEST_CASE("fork_choice_from_response", "[node][execution][grpc]") {
    const Fixtures<proto::ForkChoice, api::ForkChoice> fixtures{
        {{}, {}},
        {sample_proto_fork_choice(), sample_fork_choice()},
    };
    for (const auto& [proto_fork_choice, expected_fork_choice] : fixtures) {
        SECTION("response: " + std::to_string(proto_fork_choice.timeout())) {
            const auto fork_choice{fork_choice_from_response(proto_fork_choice)};
            CHECK(fork_choice.head_block_hash == expected_fork_choice.head_block_hash);
            CHECK(fork_choice.timeout == expected_fork_choice.timeout);
            CHECK(fork_choice.finalized_block_hash == expected_fork_choice.finalized_block_hash);
            CHECK(fork_choice.safe_block_hash == expected_fork_choice.safe_block_hash);
        }
    }
}

}  // namespace silkworm::execution::grpc::client
