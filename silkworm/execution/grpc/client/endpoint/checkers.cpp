// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "checkers.hpp"

#include <silkworm/infra/grpc/common/conversion.hpp>

namespace silkworm::execution::grpc::client {

::types::H256 h256_from_block_hash(const Hash& block_hash) {
    ::types::H256 request;
    rpc::h256_from_bytes32(block_hash, &request);
    return request;
}

std::optional<BlockNum> block_num_from_response(const ::execution::GetHeaderHashNumberResponse& reply) {
    return reply.has_block_number() ? std::make_optional(reply.block_number()) : std::nullopt;
}

api::ForkChoice fork_choice_from_response(const ::execution::ForkChoice& response) {
    api::ForkChoice fork_choice{
        .head_block_hash = rpc::bytes32_from_h256(response.head_block_hash()),
        .timeout = response.timeout(),
    };
    if (response.has_finalized_block_hash()) {
        fork_choice.finalized_block_hash = rpc::bytes32_from_h256(response.finalized_block_hash());
    }
    if (response.has_safe_block_hash()) {
        fork_choice.safe_block_hash = rpc::bytes32_from_h256(response.safe_block_hash());
    }
    return fork_choice;
}

}  // namespace silkworm::execution::grpc::client
