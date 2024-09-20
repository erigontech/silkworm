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

#include "range.hpp"

#include <silkworm/infra/grpc/common/conversion.hpp>

#include "../../common/block.hpp"

namespace silkworm::execution::grpc::client {

namespace proto = ::execution;

proto::GetBodiesByRangeRequest bodies_request_from_block_range(BlockNumRange number_range) {
    SILKWORM_ASSERT(number_range.start <= number_range.end);
    proto::GetBodiesByRangeRequest request;
    request.set_start(number_range.start);
    request.set_count(number_range.size());
    return request;
}

proto::GetBodiesByHashesRequest bodies_request_from_block_hashes(const api::BlockHashes& block_hashes) {
    proto::GetBodiesByHashesRequest request;
    for (const auto& hash : block_hashes) {
        ::types::H256* h256{request.add_hashes()};
        rpc::H256_from_bytes32(hash, h256);
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
