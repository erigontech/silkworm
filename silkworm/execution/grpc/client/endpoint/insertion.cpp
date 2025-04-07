// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "insertion.hpp"

#include "../../common/block.hpp"
#include "status.hpp"

namespace silkworm::execution::grpc::client {

namespace proto = ::execution;

proto::InsertBlocksRequest insertion_request_from_blocks(const api::Blocks& blocks) {
    proto::InsertBlocksRequest request;
    for (const auto& block : blocks) {
        proto::Block* b = request.add_blocks();
        proto::Header* header = b->mutable_header();
        proto_from_header(block->header, header);
        proto::BlockBody* body = b->mutable_body();
        proto_from_body(*block, body);
    }
    return request;
}

api::InsertionResult insertion_result_from_response(const proto::InsertionResult& response) {
    return {.status = execution_status_from_proto(response.result())};
}

}  // namespace silkworm::execution::grpc::client
