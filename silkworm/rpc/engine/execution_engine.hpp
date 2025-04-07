// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
