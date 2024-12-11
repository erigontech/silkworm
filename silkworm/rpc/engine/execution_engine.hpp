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

#pragma once

#include <chrono>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/rpc/types/execution_payload.hpp>

namespace silkworm::rpc::engine {

class ExecutionEngine {
  public:
    virtual ~ExecutionEngine() = default;

    using Msec = std::chrono::milliseconds;

    virtual Task<PayloadStatus> new_payload(const NewPayloadRequest& request, Msec timeout) = 0;
    virtual Task<ForkChoiceUpdatedReply> fork_choice_updated(const ForkChoiceUpdatedRequest& request, Msec timeout) = 0;
    virtual Task<ExecutionPayloadAndValue> get_payload(uint64_t payload_id, Msec timeout) = 0;
    virtual Task<ExecutionPayloadBodies> get_payload_bodies_by_hash(const std::vector<Hash>& block_hashes, Msec timeout) = 0;
    virtual Task<ExecutionPayloadBodies> get_payload_bodies_by_range(BlockNum start, uint64_t count, Msec timeout) = 0;
};

}  // namespace silkworm::rpc::engine
