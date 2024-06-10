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

#include "getters.hpp"

#include <optional>

#include <catch2/catch.hpp>
#include <intx/intx.hpp>

#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/infra/test_util/fixture.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>
#include <silkworm/node/test_util/sample_blocks.hpp>

#include "../../test_util/sample_protos.hpp"

namespace silkworm::execution::grpc::client {

using namespace evmc::literals;
using namespace silkworm::execution::test_util;
using namespace silkworm::test_util;
namespace proto = ::execution;

static api::BlockNumberOrHash sample_block_number_or_hash(bool has_number) {
    if (has_number) {
        return kSampleBlockNumber;
    } else {
        return kSampleBlockHash;
    }
}

static proto::GetSegmentRequest sample_proto_get_segment_request(std::optional<BlockNum> number,
                                                                 std::optional<Hash> hash) {
    proto::GetSegmentRequest request;
    if (number) {
        request.set_block_number(*number);
    }
    if (hash) {
        request.set_allocated_block_hash(rpc::H256_from_bytes32(*hash).release());
    }
    return request;
}

TEST_CASE("request_from_block_number_or_hash", "[node][execution][grpc]") {
    const Fixtures<api::BlockNumberOrHash, proto::GetSegmentRequest> fixtures{
        {{}, sample_proto_get_segment_request(0, {})},  // BlockNumberOrHash contains 1st variant as default
        {sample_block_number_or_hash(true), sample_proto_get_segment_request(kSampleBlockNumber, {})},
        {sample_block_number_or_hash(false), sample_proto_get_segment_request({}, kSampleBlockHash)},
    };
    for (const auto& [number_or_hash, expected_segment_request] : fixtures) {
        SECTION("block_number_or_hash index: " + std::to_string(number_or_hash.index())) {
            const auto segment_request{request_from_block_number_or_hash(number_or_hash)};
            // CHECK(segment_request == expected_segment_request);  // requires operator== in gRPC generated code
            CHECK(segment_request.has_block_number() == expected_segment_request.has_block_number());
            if (segment_request.has_block_number()) {
                CHECK(segment_request.block_number() == expected_segment_request.block_number());
            }
            CHECK(segment_request.has_block_hash() == expected_segment_request.has_block_hash());
            if (segment_request.has_block_hash()) {
                CHECK(segment_request.block_hash() == expected_segment_request.block_hash());
            }
        }
    }
}

static constexpr TotalDifficulty kTotalDifficulty{1'000'000};

static proto::GetTDResponse sample_td_response(bool has_value) {
    proto::GetTDResponse response;
    if (has_value) {
        response.set_allocated_td(rpc::H256_from_uint256(kTotalDifficulty).release());
    }
    return response;
}

static std::optional<TotalDifficulty> sample_total_difficulty(bool has_value) {
    return has_value ? std::make_optional(kTotalDifficulty) : std::nullopt;
}

TEST_CASE("total_difficulty_from_response", "[node][execution][grpc]") {
    const Fixtures<proto::GetTDResponse, std::optional<TotalDifficulty>> fixtures{
        {sample_td_response(false), sample_total_difficulty(false)},
        {sample_td_response(true), sample_total_difficulty(true)},
    };
    for (const auto& [response, expected_total_difficulty] : fixtures) {
        SECTION("expected_total_difficulty: " + std::to_string(expected_total_difficulty.has_value())) {
            const auto total_difficulty{total_difficulty_from_response(response)};
            CHECK(total_difficulty == expected_total_difficulty);
        }
    }
}

static proto::GetHeaderResponse sample_get_header_response() {
    proto::GetHeaderResponse response;
    sample_proto_header(response.mutable_header());
    return response;
}

TEST_CASE("header_from_response", "[node][execution][grpc]") {
    const Fixtures<proto::GetHeaderResponse, std::optional<BlockHeader>> fixtures{
        {{}, {}},
        {sample_get_header_response(), sample_block_header()},
    };
    for (const auto& [response, expected_block_header] : fixtures) {
        SECTION("expected_block_header: " + std::to_string(expected_block_header.has_value())) {
            const auto block_header{header_from_response(response)};
            CHECK(block_header == expected_block_header);
        }
    }
}

static proto::GetBodyResponse sample_get_body_response() {
    proto::GetBodyResponse response;
    sample_proto_body(response.mutable_body());
    return response;
}

TEST_CASE("body_from_response", "[node][execution][grpc]") {
    const Fixtures<proto::GetBodyResponse, std::optional<BlockBody>> fixtures{
        {{}, {}},
        {sample_get_body_response(), sample_block_body()},
    };
    for (const auto& [response, expected_block_body] : fixtures) {
        SECTION("expected_block_body: " + std::to_string(expected_block_body.has_value())) {
            const auto block_body{body_from_response(response)};
            CHECK(block_body == expected_block_body);
        }
    }
}

}  // namespace silkworm::execution::grpc::client
