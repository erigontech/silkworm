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

#include "checkers.hpp"

#include <optional>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/infra/test_util/fixture.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../test_util/sample_protos.hpp"

namespace silkworm::execution::grpc::server {

using namespace evmc::literals;
using namespace silkworm::execution::test_util;
using namespace silkworm::test_util;
namespace proto = ::execution;

static proto::GetHeaderHashNumberResponse sample_response() {
    proto::GetHeaderHashNumberResponse response;
    response.set_block_number(kSampleBlockNumber);
    return response;
}

TEST_CASE("response_from_block_number", "[node][execution][grpc]") {
    const Fixtures<std::optional<BlockNum>, proto::GetHeaderHashNumberResponse> fixtures{
        {std::nullopt, {}},
        {kSampleBlockNumber, sample_response()},
    };
    for (const auto& [block_num, expected_response] : fixtures) {
        SECTION("response: " + std::to_string(expected_response.block_number())) {
            const auto response{response_from_block_number(block_num)};
            // CHECK(response == expected_response);  // requires operator== in gRPC
            CHECK(response.has_block_number() == expected_response.has_block_number());
            if (response.has_block_number()) {
                CHECK(response.block_number() == expected_response.block_number());
            }
        }
    }
}

static constexpr auto kHeadHash{0x0000000000000000000000000000000000000000000000000000000000000001_bytes32};
static constexpr auto kFinalizedHash{0x0000000000000000000000000000000000000000000000000000000000000002_bytes32};
static constexpr auto kSafeHash{0x0000000000000000000000000000000000000000000000000000000000000003_bytes32};
static constexpr auto kTimeout{100u};

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

TEST_CASE("response_from_fork_choice", "[node][execution][grpc]") {
    const Fixtures<api::ForkChoice, proto::ForkChoice> fixtures{
        {{}, {}},
        {sample_fork_choice(), sample_proto_fork_choice()},
    };
    for (const auto& [fork_choice, expected_proto_fork_choice] : fixtures) {
        SECTION("response: " + std::to_string(fork_choice.timeout)) {
            const auto proto_fork_choice{response_from_fork_choice(fork_choice)};
            // CHECK(proto_fork_choice == expected_proto_fork_choice);  // requires operator== in gRPC
            CHECK(proto_fork_choice.head_block_hash() == expected_proto_fork_choice.head_block_hash());
            CHECK(proto_fork_choice.timeout() == expected_proto_fork_choice.timeout());
            CHECK(proto_fork_choice.has_finalized_block_hash() == expected_proto_fork_choice.has_finalized_block_hash());
            CHECK(proto_fork_choice.finalized_block_hash() == expected_proto_fork_choice.finalized_block_hash());
            CHECK(proto_fork_choice.has_safe_block_hash() == expected_proto_fork_choice.has_safe_block_hash());
            CHECK(proto_fork_choice.safe_block_hash() == expected_proto_fork_choice.safe_block_hash());
        }
    }
}

}  // namespace silkworm::execution::grpc::server
