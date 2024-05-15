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

#include "validation.hpp"

#include <silkworm/infra/grpc/common/conversion.hpp>

#include "status.hpp"

namespace silkworm::execution::grpc::server {

namespace proto = ::execution;

api::BlockNumAndHash block_num_and_hash_from_request(const proto::ValidationRequest& request) {
    return {
        .number = request.number(),
        .hash = rpc::bytes32_from_H256(request.hash()),
    };
}

proto::ValidationReceipt response_from_validation_result(const api::ValidationResult& result) {
    proto::ValidationReceipt reply;
    if (std::holds_alternative<api::ValidChain>(result)) {
        reply.set_validation_status(proto::ExecutionStatus::Success);
        const auto& valid_chain{std::get<api::ValidChain>(result)};
        reply.set_allocated_latest_valid_hash(rpc::H256_from_bytes32(valid_chain.current_head.hash).release());
    } else if (std::holds_alternative<api::InvalidChain>(result)) {
        reply.set_validation_status(proto::ExecutionStatus::InvalidForkchoice);
        const auto& invalid_chain{std::get<api::InvalidChain>(result)};
        reply.set_allocated_latest_valid_hash(rpc::H256_from_bytes32(invalid_chain.unwind_point.hash).release());
    } else if (std::holds_alternative<api::ValidationError>(result)) {
        // TODO(canepat) extend result to cover ::execution::ExecutionStatus error values
        reply.set_validation_status(proto::ExecutionStatus::InvalidForkchoice);
        const auto& validation_error{std::get<api::ValidationError>(result)};
        reply.set_validation_error(validation_error.error);
    } else {
        throw std::logic_error{"execution::grpc::server::response_from_validation_result unexpected result"};
    }
    return reply;
}

api::ForkChoice fork_choice_from_request(const proto::ForkChoice& request) {
    return {
        .head_block_hash = rpc::bytes32_from_H256(request.head_block_hash()),
        .timeout = request.timeout(),
        .finalized_block_hash = rpc::bytes32_from_H256(request.finalized_block_hash()),
        .safe_block_hash = rpc::bytes32_from_H256(request.safe_block_hash()),
    };
}

proto::ForkChoiceReceipt response_from_fork_choice_result(const api::ForkChoiceResult& result) {
    proto::ForkChoiceReceipt reply;
    reply.set_status(proto_from_execution_status(result.status));
    reply.set_allocated_latest_valid_hash(rpc::H256_from_bytes32(result.latest_valid_head).release());
    reply.set_validation_error(result.validation_error);
    return reply;
}

}  // namespace silkworm::execution::grpc::server
