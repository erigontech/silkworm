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

#include "checkers.hpp"

namespace silkworm::execution::grpc::server {

::execution::GetHeaderHashNumberResponse response_from_block_number(std::optional<BlockNum> block_number) {
    ::execution::GetHeaderHashNumberResponse response;
    if (block_number) {
        response.set_block_number(*block_number);
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
