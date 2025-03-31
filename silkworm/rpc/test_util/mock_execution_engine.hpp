// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/engine/execution_engine.hpp>

namespace silkworm::rpc::test_util {

class ExecutionEngineMock : public engine::ExecutionEngine {  // NOLINT
  public:
    MOCK_METHOD((Task<ExecutionPayloadAndValue>), get_payload, (uint64_t, Msec));
    MOCK_METHOD((Task<PayloadStatus>), new_payload, (const NewPayloadRequest&, Msec));
    MOCK_METHOD((Task<ForkChoiceUpdatedReply>), fork_choice_updated, (const ForkChoiceUpdatedRequest&, Msec));
    MOCK_METHOD((Task<ExecutionPayloadBodies>), get_payload_bodies_by_hash, (const std::vector<Hash>&, Msec));
    MOCK_METHOD((Task<ExecutionPayloadBodies>), get_payload_bodies_by_range, (BlockNum start, uint64_t count, Msec));
};

}  // namespace silkworm::rpc::test_util
