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

namespace silkworm::execution::grpc::client {

namespace proto = ::execution;

proto::ValidationRequest request_from_block_num_and_hash(const BlockId& number_and_hash) {
    proto::ValidationRequest request;
    request.set_number(number_and_hash.number);
    request.set_allocated_hash(rpc::h256_from_bytes32(number_and_hash.hash).release());
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
