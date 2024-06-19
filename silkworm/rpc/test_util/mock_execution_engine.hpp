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
