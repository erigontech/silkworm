/*
   Copyright 2021 The Silkworm Authors

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

#include "block_provider.hpp"

#include <chrono>
#include <thread>

#include <silkworm/common/log.hpp>

#include "internals/header_retrieval.hpp"
#include "messages/InboundMessage.hpp"
#include "rpc/receive_messages.hpp"

namespace silkworm {

BlockProvider::BlockProvider(SentryClient& sentry, const Db::ReadOnlyAccess& db_access)
    : db_access_{db_access}, sentry_{sentry} {}

BlockProvider::~BlockProvider() {
    stop();
    log::Error() << "BlockProvider destroyed";
}

void BlockProvider::receive_message(const sentry::InboundMessage& raw_message) {
    auto message = InboundBlockRequestMessage::make(raw_message, db_access_, sentry_);

    SILK_TRACE << "BlockProvider received message " << *message;

    messages_.push(message);
}

void BlockProvider::execution_loop() {
    using namespace std::chrono_literals;

    sentry_.subscribe(SentryClient::Scope::BlockRequests,
                      [this](const sentry::InboundMessage& msg) { receive_message(msg); });

    while (!is_stopping() && !sentry_.is_stopping()) {
        // pop a message from the queue
        std::shared_ptr<InboundMessage> message;
        bool present = messages_.timed_wait_and_pop(message, 1000ms);
        if (!present) continue;  // timeout, needed to check exiting_

        // process the message (command pattern)
        SILK_TRACE << "BlockProvider processing message " << *message;
        message->execute();
    }

    stop();
    log::Warning() << "BlockProvider execution_loop is stopping...";
}

}  // namespace silkworm
