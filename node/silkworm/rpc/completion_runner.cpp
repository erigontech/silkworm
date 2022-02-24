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

#include <silkworm/rpc/completion_tag.hpp>

namespace silkworm::rpc {

void CompletionRunner::stop() {
    SILK_TRACE << "CompletionRunner::stop start started: " << started_ << " shutdown: " << shutdown_requested_;
    std::unique_lock<std::mutex> lock(mutex_);
    if (!shutdown_requested_) {
        shutdown_requested_ = true;
        if (started_) {
            SILK_DEBUG << "CompletionRunner::stop set shutdown alarm";
            auto shutdown_alarm = std::make_unique<grpc::Alarm>();
            TagProcessor shutdown_processor = [this](bool ok) { shutdown(ok); };
            shutdown_alarm->Set(&queue_, gpr_now(GPR_CLOCK_MONOTONIC), reinterpret_cast<void*>(&shutdown_processor));
            SILK_DEBUG << "CompletionRunner::stop waiting for clean up...";
            shutdown_completed_.wait(lock);
        } else {
            // The completion runner has not been started, so no chance to ask the scheduler to shutdown.
            // Just shutdown and drain queue on the calling thread is fine.
            shutdown(false);
        }
    }
    SILK_TRACE << "CompletionRunner::stop end";
}

void CompletionRunner::run() {
    SILK_TRACE << "CompletionRunner::run start";
    {
        std::unique_lock<std::mutex> lock(mutex_);
        started_ = true;
    }
    bool running = true;
    while (running) {
        CompletionTag tag;
        const auto got_event = queue_.Next(reinterpret_cast<void**>(&tag.processor), &tag.ok);
        if (got_event) {
            SILK_DEBUG << "CompletionRunner::run post operation: " << &tag.processor;
            io_context_.post([=]() { (*tag.processor)(tag.ok); });
        } else {
            running = false;
            SILK_DEBUG << "CompletionRunner::run queue shutdown";
        }
    }
    SILK_TRACE << "CompletionRunner::run end";
}

void CompletionRunner::shutdown(bool ok) {
    SILK_TRACE << "CompletionRunner::shutdown start ok: " << ok;
    queue_.Shutdown();
    SILK_DEBUG << "CompletionRunner::shutdown draining...";
    void* ignored_tag;
    bool ignored_ok;
    while (queue_.Next(&ignored_tag, &ignored_ok)) {}
    shutdown_completed_.notify_all();
    SILK_TRACE << "CompletionRunner::shutdown end";
}

} // namespace silkworm::rpc
