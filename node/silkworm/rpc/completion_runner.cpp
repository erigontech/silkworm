/*
   Copyright 2022 The Silkworm Authors

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

#include "completion_runner.hpp"

#include <memory>

#include <grpcpp/alarm.h>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/completion_tag.hpp>

namespace silkworm::rpc {

int CompletionRunner::poll_one() {
    SILK_TRACE << "CompletionRunner::poll_one START";

    int num_completed{0}; // returned when next_status == grpc::CompletionQueue::TIMEOUT

    void* tag{nullptr};
    bool ok{false};
    const auto next_status = queue_.AsyncNext(&tag, &ok, gpr_time_0(GPR_CLOCK_MONOTONIC));
    if (next_status == grpc::CompletionQueue::GOT_EVENT) {
        num_completed = 1;
        // Handle the event completion on the calling thread (*must* be the io_context scheduler).
        CompletionTag completion_tag{reinterpret_cast<TagProcessor*>(tag), ok};
        SILK_DEBUG << "CompletionRunner::poll_one post operation: " << completion_tag.processor;
        (*completion_tag.processor)(completion_tag.ok);
    } else if (next_status == grpc::CompletionQueue::SHUTDOWN) {
        num_completed = -1;
    }

    SILK_TRACE << "CompletionRunner::poll_one next_status=" << next_status << " END";
    return num_completed;
}

void CompletionRunner::shutdown() {
    SILK_TRACE << "CompletionRunner::shutdown START";
    queue_.Shutdown();
    SILK_DEBUG << "CompletionRunner::shutdown draining...";
    void* ignored_tag;
    bool ignored_ok;
    while (queue_.Next(&ignored_tag, &ignored_ok)) {
    }
    SILK_TRACE << "CompletionRunner::shutdown END";
}

}  // namespace silkworm::rpc
