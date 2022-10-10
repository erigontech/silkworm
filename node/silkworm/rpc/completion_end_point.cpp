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

#include "completion_end_point.hpp"

#include <boost/asio/post.hpp>
#include <grpcpp/alarm.h>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/completion_tag.hpp>

namespace silkworm::rpc {

std::size_t CompletionEndPoint::poll_one() {
    std::size_t num_completed{0};

    void* tag{nullptr};
    bool ok{false};
    const auto next_status = queue_.AsyncNext(&tag, &ok, gpr_time_0(GPR_CLOCK_MONOTONIC));
    if (next_status == grpc::CompletionQueue::GOT_EVENT) {
        num_completed = 1;
        // Handle the event completion on the calling thread (*must* be the io_context scheduler).
        CompletionTag completion_tag{reinterpret_cast<TagProcessor*>(tag), ok};
        SILK_DEBUG << "CompletionEndPoint::poll_one post operation: " << completion_tag.processor;
        (*completion_tag.processor)(completion_tag.ok);
    } else if (next_status == grpc::CompletionQueue::SHUTDOWN) {
        closed_ = true;
        SILK_DEBUG << "CompletionEndPoint::poll_one shutdown";
    }

    return num_completed;
}

bool CompletionEndPoint::post_one(boost::asio::io_context& scheduler) {
    SILK_TRACE << "CompletionEndPoint::post_one START";
    void* tag{nullptr};
    bool ok{false};
    const auto got_event = queue_.Next(&tag, &ok);
    if (got_event) {
        // Post the event completion on the passed io_context scheduler.
        CompletionTag completion_tag{reinterpret_cast<TagProcessor*>(tag), ok};
        SILK_DEBUG << "CompletionEndPoint::post_one post operation: " << completion_tag.processor;
        boost::asio::post(scheduler, [completion_tag]() {
            (*completion_tag.processor)(completion_tag.ok);
        });
    } else {
        SILK_DEBUG << "CompletionEndPoint::run shutdown";
    }
    SILK_TRACE << "CompletionEndPoint::post_one got_event=" << got_event << " END";
    return !got_event;
}

void CompletionEndPoint::shutdown() {
    SILK_TRACE << "CompletionEndPoint::shutdown START";
    queue_.Shutdown();
    SILK_DEBUG << "CompletionEndPoint::shutdown draining...";
    void* ignored_tag;
    bool ignored_ok;
    while (queue_.Next(&ignored_tag, &ignored_ok)) {
    }
    SILK_TRACE << "CompletionEndPoint::shutdown END";
}

}  // namespace silkworm::rpc
