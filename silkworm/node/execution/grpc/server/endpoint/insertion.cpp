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

#include "insertion.hpp"

#include "../../common/block.hpp"
#include "status.hpp"

namespace silkworm::execution::grpc::server {

namespace proto = ::execution;

api::Blocks blocks_from_insertion_request(const proto::InsertBlocksRequest& request) {
    api::Blocks blocks;
    for (int index{0}; index < request.blocks_size(); ++index) {
        const auto& request_block{request.blocks(index)};
        auto block{std::make_shared<Block>()};
        header_from_proto(request_block.header(), block->header);
        Hash block_hash;
        body_from_proto(request_block.body(), *block, block_hash, block->header.number);
        SILKWORM_ASSERT(block->header.hash() == block_hash);
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
