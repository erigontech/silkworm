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
