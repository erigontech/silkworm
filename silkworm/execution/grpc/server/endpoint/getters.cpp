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

#include "getters.hpp"

#include <silkworm/infra/grpc/common/conversion.hpp>

#include "../../common/block.hpp"

namespace silkworm::execution::grpc::server {

namespace proto = ::execution;

api::BlockNumberOrHash block_number_or_hash_from_request(const proto::GetSegmentRequest& request) {
    api::BlockNumberOrHash number_or_hash;
    if (request.has_block_number()) {
        number_or_hash = request.block_number();
    } else if (request.has_block_hash()) {
        number_or_hash = rpc::bytes32_from_h256(request.block_hash());
    }
    return number_or_hash;
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

proto::GetBodyResponse response_from_body(const std::optional<BlockBody>& body, const Hash& block_hash, BlockNum block_number) {
    proto::GetBodyResponse response;
    if (body) {
        proto::BlockBody* proto_body = response.mutable_body();
        proto_from_body(*body, block_hash, block_number, proto_body);
    }
    return response;
}

}  // namespace silkworm::execution::grpc::server
