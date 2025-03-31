// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "getters.hpp"

#include <silkworm/infra/grpc/common/conversion.hpp>

#include "../../common/block.hpp"

namespace silkworm::execution::grpc::server {

namespace proto = ::execution;

api::BlockNumOrHash block_num_or_hash_from_request(const proto::GetSegmentRequest& request) {
    api::BlockNumOrHash block_num_or_hash;
    if (request.has_block_number()) {
        block_num_or_hash = request.block_number();
    } else if (request.has_block_hash()) {
        block_num_or_hash = rpc::bytes32_from_h256(request.block_hash());
    }
    return block_num_or_hash;
}

proto::GetTDResponse response_from_total_difficulty(const std::optional<TotalDifficulty>& total_difficulty) {
    proto::GetTDResponse response;
    if (total_difficulty) {
        response.set_allocated_td(rpc::h256_from_uint256(*total_difficulty).release());
    }
    return response;
}

proto::GetHeaderResponse response_from_header(const std::optional<BlockHeader>& header) {
    proto::GetHeaderResponse response;
    if (header) {
        proto::Header* proto_header = response.mutable_header();
        proto_from_header(*header, proto_header);
    }
    return response;
}

proto::GetBodyResponse response_from_body(const std::optional<BlockBody>& body, const Hash& block_hash, BlockNum block_num) {
    proto::GetBodyResponse response;
    if (body) {
        proto::BlockBody* proto_body = response.mutable_body();
        proto_from_body(*body, block_hash, block_num, proto_body);
    }
    return response;
}

}  // namespace silkworm::execution::grpc::server
