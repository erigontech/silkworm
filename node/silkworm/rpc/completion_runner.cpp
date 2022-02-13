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

#include <functional>

#include <silkworm/rpc/completion_tag.hpp>

namespace silkworm::rpc {

void CompletionRunner::stop() {
    SILK_INFO << "CompletionRunner::stop start shutting down...";
    queue_.Shutdown();
    SILK_INFO << "CompletionRunner::stop end";
}

void CompletionRunner::run() {
    SILK_INFO << "CompletionRunner::run start";
    bool running = true;
    while (running) {
        CompletionTag tag;
        const auto got_event = queue_.Next(reinterpret_cast<void**>(&tag.processor), &tag.ok);
        if (got_event) {
            SILK_TRACE << "CompletionRunner::run post operation: " << &tag.processor;
            io_context_.post([=]() { (*tag.processor)(tag.ok); });
        } else {
            running = false;
            SILK_DEBUG << "CompletionRunner::run queue shutdown";
        }
    }
    SILK_INFO << "CompletionRunner::run end";
}

} // namespace silkworm::rpc
