// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "insertion.hpp"

#include "../../common/block.hpp"
#include "status.hpp"

namespace silkworm::execution::grpc::server {

namespace proto = ::execution;

std::optional<api::Blocks> blocks_from_insertion_request(const proto::InsertBlocksRequest& request) {
    api::Blocks blocks;
    for (int index{0}; index < request.blocks_size(); ++index) {
        const auto& request_block{request.blocks(index)};
        auto block{std::make_shared<Block>()};
        header_from_proto(request_block.header(), block->header);
        Hash block_hash;
        body_from_proto(request_block.body(), *block, block_hash, block->header.number);
        if (block->header.hash() != block_hash) {
            return {};
        }
        blocks.emplace_back(std::move(block));
    }
    return blocks;
}

proto::InsertionResult response_from_insertion_result(const api::InsertionResult& result) {
    proto::InsertionResult response;
    response.set_result(proto_from_execution_status(result.status));
    return response;
}

}  // namespace silkworm::execution::grpc::server
