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
#include <silkworm/interfaces/execution/execution.pb.h>
#include <silkworm/node/test_util/fixture.hpp>
#include <silkworm/node/test_util/sample_blocks.hpp>

#include "../../../test_util/sample_protos.hpp"

namespace silkworm::execution::grpc::server {

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

TEST_CASE("block_number_or_hash_from_request", "[node][execution][grpc]") {
    const Fixtures<proto::GetSegmentRequest, api::BlockNumberOrHash> fixtures{
        {sample_proto_get_segment_request({}, {}), {}},  // BlockNumberOrHash contains 1st variant as default
        {sample_proto_get_segment_request(0, {}), {}},  // BlockNumberOrHash contains 1st variant as default
        {sample_proto_get_segment_request(kSampleBlockNumber, {}), sample_block_number_or_hash(true)},
        {sample_proto_get_segment_request({}, kSampleBlockHash), sample_block_number_or_hash(false)},
    };
    for (const auto& [segment_request, expected_number_or_hash] : fixtures) {
        SECTION("block_number_or_hash index: " + std::to_string(expected_number_or_hash.index())) {
            const auto number_or_hash{block_number_or_hash_from_request(segment_request)};
            CHECK(number_or_hash == expected_number_or_hash);
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

TEST_CASE("response_from_total_difficulty", "[node][execution][grpc]") {
    const Fixtures<std::optional<TotalDifficulty>, proto::GetTDResponse> fixtures{
        {sample_total_difficulty(false), sample_td_response(false)},
        {sample_total_difficulty(true), sample_td_response(true)},
    };
    for (const auto& [total_difficulty, expected_response] : fixtures) {
        SECTION("total_difficulty: " + std::to_string(total_difficulty.has_value())) {
            const auto response{response_from_total_difficulty(total_difficulty)};
            // CHECK(response == expected_response);  // requires operator== in gRPC
            CHECK(response.has_td() == expected_response.has_td());
            if (response.has_td()) {
                CHECK(response.td() == expected_response.td());
            }
        }
    }
}

static proto::GetHeaderResponse sample_get_header_response() {
    proto::GetHeaderResponse response;
    proto::Header* proto_header = response.mutable_header();
    sample_proto_header(proto_header);
    proto_header->set_allocated_block_hash(rpc::H256_from_bytes32(kSampleBlockHash).release());
    return response;
}

TEST_CASE("response_from_header", "[node][execution][grpc]") {
    const Fixtures<std::optional<BlockHeader>, proto::GetHeaderResponse> fixtures{
        {{}, {}},
        {sample_block_header(), sample_get_header_response()},
    };
    for (const auto& [block_header, expected_response] : fixtures) {
        SECTION("block_header: " + std::to_string(block_header.has_value())) {
            const auto response{response_from_header(block_header)};
            // CHECK(response == expected_response);  // requires operator== in gRPC generated code
            CHECK(response.has_header() == expected_response.has_header());
            if (response.has_header()) {
                const auto& header{response.header()};
                const auto& expected_header{expected_response.header()};
                CHECK(header.block_number() == expected_header.block_number());
                CHECK(header.has_block_hash() == expected_header.has_block_hash());
                CHECK(header.block_hash() == expected_header.block_hash());
                CHECK(header.extra_data() == expected_header.extra_data());
                CHECK(header.parent_hash() == expected_header.parent_hash());
            }
        }
    }
}

static proto::GetBodyResponse sample_get_body_response() {
    proto::GetBodyResponse response;
    sample_proto_body(response.mutable_body());
    return response;
}

TEST_CASE("response_from_body", "[node][execution][grpc]") {
    const Fixtures<std::optional<BlockBody>, proto::GetBodyResponse> fixtures{
        {{}, {}},
        {sample_block_body(), sample_get_body_response()},
    };
    for (const auto& [block_body, expected_response] : fixtures) {
        SECTION("block_body: " + std::to_string(block_body.has_value())) {
            const auto response{response_from_body(block_body, kSampleBlockHash, kSampleBlockNumber)};
            // CHECK(response == expected_response);  // requires operator== in gRPC generated code
            CHECK(response.has_body() == expected_response.has_body());
            if (response.has_body()) {
                const auto& body{response.body()};
                const auto& expected_body{expected_response.body()};
                CHECK(body.block_hash() == expected_body.block_hash());
                CHECK(body.block_number() == expected_body.block_number());
                CHECK(body.transactions_size() == expected_body.transactions_size());
                CHECK(body.uncles_size() == expected_body.uncles_size());
                CHECK(body.withdrawals_size() == expected_body.withdrawals_size());
            }
        }
    }
}

}  // namespace silkworm::execution::grpc::server
