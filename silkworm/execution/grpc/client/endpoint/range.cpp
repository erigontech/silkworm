// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "range.hpp"

#include <silkworm/infra/grpc/common/conversion.hpp>

#include "../../common/block.hpp"

namespace silkworm::execution::grpc::client {

namespace proto = ::execution;

proto::GetBodiesByRangeRequest bodies_request_from_block_num_range(BlockNumRange block_num_range) {
    SILKWORM_ASSERT(block_num_range.start <= block_num_range.end);
    proto::GetBodiesByRangeRequest request;
    request.set_start(block_num_range.start);
    request.set_count(block_num_range.size());
    return request;
}

proto::GetBodiesByHashesRequest bodies_request_from_block_hashes(const api::BlockHashes& block_hashes) {
    proto::GetBodiesByHashesRequest request;
    for (const auto& hash : block_hashes) {
        ::types::H256* h256{request.add_hashes()};
        rpc::h256_from_bytes32(hash, h256);
    }
    return request;
}

api::BlockBodies block_bodies_from_response(const proto::GetBodiesBatchResponse& response) {
    api::BlockBodies bodies;
    bodies.reserve(static_cast<size_t>(response.bodies_size()));
    for (const auto& received_body : response.bodies()) {
        bodies.emplace_back(body_from_proto(received_body));
    }
    return bodies;
}

}  // namespace silkworm::execution::grpc::client
