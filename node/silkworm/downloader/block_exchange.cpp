/*
Copyright 2021-2022 The Silkworm Authors

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

#include "block_exchange.hpp"

#include <chrono>
#include <thread>

#include <silkworm/common/log.hpp>
#include <silkworm/downloader/internals/preverified_hashes.hpp>
#include <silkworm/downloader/messages/inbound_message.hpp>

namespace silkworm {

BlockExchange::BlockExchange(SentryClient& sentry, const Db::ReadOnlyAccess& dba, const ChainIdentity& ci)
    : db_access_{dba},
      sentry_{sentry},
      chain_identity_{ci},
      header_chain_{ci},
      body_sequence_{dba, ci} {
    auto tx = db_access_.start_ro_tx();
    header_chain_.recover_initial_state(tx);
    header_chain_.set_preverified_hashes(PreverifiedHashes::load(ci.chain.chain_id));
}

BlockExchange::~BlockExchange() {
    stop();
    log::Error() << "BlockExchange destroyed";
}

const ChainIdentity& BlockExchange::chain_identity() {
    return chain_identity_;
}

void BlockExchange::accept(std::shared_ptr<Message> message) { messages_.push(message); }

void BlockExchange::receive_message(const sentry::InboundMessage& raw_message) {
    try {
        auto message = InboundMessage::make(raw_message);

        SILK_TRACE << "BlockExchange received message " << *message;

        messages_.push(message);
    }
    catch(rlp::DecodingError& error) {
        log::Warning() << "BlockExchange received and ignored a malformed message, "
                          "id=" << raw_message.id() << "/" << sentry::MessageId_Name(raw_message.id());
    }
}

void BlockExchange::execution_loop() {
    using namespace std::chrono;
    using namespace std::chrono_literals;

    sentry_.subscribe(SentryClient::Scope::BlockAnnouncements,
                      [this](const sentry::InboundMessage& msg) { receive_message(msg); });
    sentry_.subscribe(SentryClient::Scope::BlockRequests,
                      [this](const sentry::InboundMessage& msg) { receive_message(msg); });

    auto constexpr kShortInterval = 1000ms;
    time_point_t last_update = system_clock::now();

    while (!is_stopping() && !sentry_.is_stopping()) {
        // pop a message from the queue
        std::shared_ptr<Message> message;
        bool present = messages_.timed_wait_and_pop(message, kShortInterval);
        if (!present) continue;  // timeout, needed to check exiting_

        // process the message (command pattern)
        message->execute(db_access_, header_chain_, body_sequence_, sentry_);

        // log status
        if (system_clock::now() - last_update > 30s) {
            last_update = system_clock::now();
            if (silkworm::log::test_verbosity(silkworm::log::Level::kDebug)) {
                log::Debug() << "BlockExchange headers | " << std::setfill(' ')
                             << "status: " << header_chain_.human_readable_status() << " | "
                             << "stats: " << header_chain_.human_readable_stats();
                log::Debug() << "BlockExchange bodies | " << std::setfill(' ')
                             << "status: " << body_sequence_.human_readable_status() << " | "
                             << "stats: " << body_sequence_.human_readable_stats();
            }
        }

    }

    stop();
    log::Warning() << "BlockExchange execution_loop is stopping...";
}

}  // namespace silkworm
