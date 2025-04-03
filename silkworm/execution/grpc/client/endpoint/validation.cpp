// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "validation.hpp"

#include <silkworm/infra/grpc/common/conversion.hpp>

#include "status.hpp"

namespace silkworm::execution::grpc::client {

namespace proto = ::execution;

proto::ValidationRequest request_from_block_id(const BlockId& block_id) {
    proto::ValidationRequest request;
    request.set_number(block_id.block_num);
    request.set_allocated_hash(rpc::h256_from_bytes32(block_id.hash).release());
    return request;
}

api::ValidationResult validation_result_from_response(const proto::ValidationReceipt& receipt) {
    api::ValidationResult result;
    const Hash latest_valid_head{rpc::bytes32_from_h256(receipt.latest_valid_hash())};
    if (receipt.validation_status() == proto::ExecutionStatus::Success) {
        result = api::ValidChain{
            .current_head = BlockId{.hash = latest_valid_head},
        };
    } else if (receipt.validation_status() == proto::ExecutionStatus::InvalidForkchoice) {
        result = api::InvalidChain{
            .unwind_point = BlockId{.hash = latest_valid_head},
        };
    } else {
        result = api::ValidationError{
            .latest_valid_head = BlockId{.hash = latest_valid_head},
            .error = receipt.validation_error(),
        };
    }
    return result;
}

proto::ForkChoice request_from_fork_choice(const api::ForkChoice& fork_choice) {
    proto::ForkChoice request;
    request.set_allocated_head_block_hash(rpc::h256_from_bytes32(fork_choice.head_block_hash).release());
    request.set_timeout(fork_choice.timeout);
    if (fork_choice.finalized_block_hash) {
        request.set_allocated_finalized_block_hash(rpc::h256_from_bytes32(*fork_choice.finalized_block_hash).release());
    }
    if (fork_choice.safe_block_hash) {
        request.set_allocated_safe_block_hash(rpc::h256_from_bytes32(*fork_choice.safe_block_hash).release());
    }
    return request;
}

api::ForkChoiceResult fork_choice_result_from_response(const proto::ForkChoiceReceipt& receipt) {
    return {
        .status = execution_status_from_proto(receipt.status()),
        .latest_valid_head = rpc::bytes32_from_h256(receipt.latest_valid_hash()),
        .validation_error = receipt.validation_error(),
    };
}

}  // namespace silkworm::execution::grpc::client
