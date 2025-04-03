// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "range.hpp"

#include <silkworm/infra/grpc/common/conversion.hpp>

#include "../../common/block.hpp"

namespace silkworm::execution::grpc::server {

namespace proto = ::execution;

BlockNumRange block_num_range_from_request(const proto::GetBodiesByRangeRequest& request) {
    return {request.start(), request.start() + request.count()};
}

api::BlockHashes block_hashes_from_request(const proto::GetBodiesByHashesRequest& request) {
    api::BlockHashes hashes;
    hashes.reserve(static_cast<size_t>(request.hashes_size()));
    for (const auto& h256 : request.hashes()) {
        hashes.emplace_back(rpc::bytes32_from_h256(h256));
    }
    return hashes;
}

proto::GetBodiesBatchResponse response_from_bodies(const api::BlockBodies& bodies) {
    proto::GetBodiesBatchResponse response;
    for (const auto& body : bodies) {
        proto::BlockBody* proto_body{response.add_bodies()};
        proto_from_body(body, proto_body);
    }
    return response;
}

}  // namespace silkworm::execution::grpc::server
