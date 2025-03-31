// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "getters.hpp"

#include <optional>

#include <catch2/catch_test_macros.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/test_util/sample_blocks.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/infra/test_util/fixture.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../test_util/sample_protos.hpp"

namespace silkworm::execution::grpc::client {

using namespace evmc::literals;
using namespace silkworm::execution::test_util;
using namespace silkworm::test_util;
namespace proto = ::execution;

static api::BlockNumOrHash sample_block_num_or_hash(bool has_number) {
    if (has_number) {
        return kSampleBlockNum;
    }
    return kSampleBlockHash;
}

static proto::GetSegmentRequest sample_proto_get_segment_request(
    std::optional<BlockNum> block_num,
    std::optional<Hash> hash) {
    proto::GetSegmentRequest request;
    if (block_num) {
        request.set_block_number(*block_num);
    }
    if (hash) {
        request.set_allocated_block_hash(rpc::h256_from_bytes32(*hash).release());
    }
    return request;
}

TEST_CASE("request_from_block_num_or_hash", "[node][execution][grpc]") {
    const Fixtures<api::BlockNumOrHash, proto::GetSegmentRequest> fixtures{
        {{}, sample_proto_get_segment_request(0, {})},  // BlockNumOrHash contains 1st variant as default
        {sample_block_num_or_hash(true), sample_proto_get_segment_request(kSampleBlockNum, {})},
        {sample_block_num_or_hash(false), sample_proto_get_segment_request({}, kSampleBlockHash)},
    };
    for (const auto& [block_num_or_hash, expected_segment_request] : fixtures) {
        SECTION("block_num_or_hash index: " + std::to_string(block_num_or_hash.index())) {
            const auto segment_request{request_from_block_num_or_hash(block_num_or_hash)};
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
        response.set_allocated_td(rpc::h256_from_uint256(kTotalDifficulty).release());
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
