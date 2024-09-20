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

namespace silkworm::execution::grpc::server {

namespace proto = ::execution;

BlockNumRange block_num_range_from_request(const proto::GetBodiesByRangeRequest& request) {
    return {request.start(), request.start() + request.count()};
}

api::BlockHashes block_hashes_from_request(const proto::GetBodiesByHashesRequest& request) {
    api::BlockHashes hashes;
    hashes.reserve(static_cast<size_t>(request.hashes_size()));
    for (const auto& h256 : request.hashes()) {
        hashes.emplace_back(rpc::bytes32_from_H256(h256));
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
