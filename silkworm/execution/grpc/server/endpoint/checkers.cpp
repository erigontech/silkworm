// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "checkers.hpp"

namespace silkworm::execution::grpc::server {

::execution::GetHeaderHashNumberResponse response_from_block_num(std::optional<BlockNum> block_num) {
    ::execution::GetHeaderHashNumberResponse response;
    if (block_num) {
        response.set_block_number(*block_num);
    }
    return response;
}

::execution::ForkChoice response_from_fork_choice(const api::ForkChoice& fork_choice) {
    ::execution::ForkChoice response;
    response.set_allocated_head_block_hash(rpc::h256_from_bytes32(fork_choice.head_block_hash).release());
    response.set_timeout(fork_choice.timeout);
    if (fork_choice.finalized_block_hash) {
        response.set_allocated_finalized_block_hash(rpc::h256_from_bytes32(*fork_choice.finalized_block_hash).release());
    }
    if (fork_choice.safe_block_hash) {
        response.set_allocated_safe_block_hash(rpc::h256_from_bytes32(*fork_choice.safe_block_hash).release());
    }
    return response;
}

}  // namespace silkworm::execution::grpc::server
