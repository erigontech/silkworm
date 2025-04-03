// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "getters.hpp"

#include <silkworm/infra/grpc/common/conversion.hpp>

#include "../../common/block.hpp"

namespace silkworm::execution::grpc::client {

::execution::GetSegmentRequest request_from_block_num_or_hash(const api::BlockNumOrHash& block_num_or_hash) {
    ::execution::GetSegmentRequest request;
    if (std::holds_alternative<Hash>(block_num_or_hash)) {
        const auto& block_hash{std::get<Hash>(block_num_or_hash)};
        request.set_allocated_block_hash(rpc::h256_from_bytes32(block_hash).release());
    } else {
        SILKWORM_ASSERT(std::holds_alternative<BlockNum>(block_num_or_hash));
        const auto block_num{std::get<BlockNum>(block_num_or_hash)};
        request.set_block_number(block_num);
    }
    return request;
}

std::optional<TotalDifficulty> total_difficulty_from_response(const ::execution::GetTDResponse& response) {
    if (!response.has_td()) {
        return {};
    }
    return rpc::uint256_from_h256(response.td());
}

std::optional<BlockHeader> header_from_response(const ::execution::GetHeaderResponse& response) {
    if (!response.has_header()) {
        return {};
    }
    return header_from_proto(response.header());
}

std::optional<BlockBody> body_from_response(const ::execution::GetBodyResponse& response) {
    if (!response.has_body()) {
        return {};
    }
    return body_from_proto(response.body());
}

}  // namespace silkworm::execution::grpc::client
