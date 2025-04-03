// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "validation.hpp"

#include <silkworm/infra/grpc/common/conversion.hpp>

#include "status.hpp"

namespace silkworm::execution::grpc::server {

namespace proto = ::execution;

BlockId block_id_from_request(const proto::ValidationRequest& request) {
    return {
        .block_num = request.number(),
        .hash = rpc::bytes32_from_h256(request.hash()),
    };
}

proto::ValidationReceipt response_from_validation_result(const api::ValidationResult& result) {
    proto::ValidationReceipt reply;
    if (std::holds_alternative<api::ValidChain>(result)) {
        reply.set_validation_status(proto::ExecutionStatus::Success);
        const auto& valid_chain{std::get<api::ValidChain>(result)};
        reply.set_allocated_latest_valid_hash(rpc::h256_from_bytes32(valid_chain.current_head.hash).release());
    } else if (std::holds_alternative<api::InvalidChain>(result)) {
        reply.set_validation_status(proto::ExecutionStatus::InvalidForkchoice);
        const auto& invalid_chain{std::get<api::InvalidChain>(result)};
        reply.set_allocated_latest_valid_hash(rpc::h256_from_bytes32(invalid_chain.unwind_point.hash).release());
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
        .head_block_hash = rpc::bytes32_from_h256(request.head_block_hash()),
        .timeout = request.timeout(),
        .finalized_block_hash = rpc::bytes32_from_h256(request.finalized_block_hash()),
        .safe_block_hash = rpc::bytes32_from_h256(request.safe_block_hash()),
    };
}

proto::ForkChoiceReceipt response_from_fork_choice_result(const api::ForkChoiceResult& result) {
    proto::ForkChoiceReceipt reply;
    reply.set_status(proto_from_execution_status(result.status));
    reply.set_allocated_latest_valid_hash(rpc::h256_from_bytes32(result.latest_valid_head).release());
    reply.set_validation_error(result.validation_error);
    return reply;
}

}  // namespace silkworm::execution::grpc::server
