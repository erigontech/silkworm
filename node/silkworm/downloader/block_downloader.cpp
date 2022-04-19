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

#include <chrono>
#include <thread>

#include <silkworm/common/log.hpp>

#include <silkworm/consensus/engine.hpp>
#include <silkworm/downloader/internals/preverified_hashes.hpp>
#include <silkworm/downloader/messages/outbound_get_block_headers.hpp>
#include <silkworm/downloader/messages/inbound_message.hpp>

#include "block_downloader.hpp"

namespace silkworm {

BlockDownloader::BlockDownloader(SentryClient& sentry, const Db::ReadOnlyAccess& dba, const ChainIdentity& ci)
    : db_access_{dba}, sentry_{sentry}, header_chain_(consensus::engine_factory(ci.chain)), body_sequence_() {
    auto tx = db_access_.start_ro_tx();
    header_chain_.recover_initial_state(tx);
    header_chain_.set_preverified_hashes(PreverifiedHashes::load(ci.chain.chain_id));
}

BlockDownloader::~BlockDownloader() {
    stop();
    log::Error() << "BlockDownloader destroyed";
}

void BlockDownloader::accept(std::shared_ptr<Message> message) { messages_.push(message); }

void BlockDownloader::receive_message(const sentry::InboundMessage& raw_message) {
    auto message = InboundMessage::make(raw_message);

    SILK_TRACE << "BlockDownloader received message " << *message;

    messages_.push(message);
}

void BlockDownloader::execution_loop() {
    using namespace std::chrono;
    using namespace std::chrono_literals;

    sentry_.subscribe(SentryClient::Scope::BlockAnnouncements,
                      [this](const sentry::InboundMessage& msg) { receive_message(msg); });
    sentry_.subscribe(SentryClient::Scope::BlockRequests,
                      [this](const sentry::InboundMessage& msg) { receive_message(msg); });

    auto constexpr kShortInterval = 1000ms;

    while (!is_stopping() && !sentry_.is_stopping()) {
        // pop a message from the queue
        std::shared_ptr<Message> message;
        bool present = messages_.timed_wait_and_pop(message, kShortInterval);
        if (!present) continue;  // timeout, needed to check exiting_

        // process the message (command pattern)
        message->execute(db_access_, header_chain_, body_sequence_, sentry_);

        // log status
        if (silkworm::log::test_verbosity(silkworm::log::Level::kTrace)) {
            auto out_message = std::dynamic_pointer_cast<OutboundGetBlockHeaders>(message);
            auto reqs = out_message != nullptr ? out_message->sent_request() : 0;
            uint64_t rejected_headers =
                header_chain_.statistics_.received_headers - header_chain_.statistics_.accepted_headers;
            log::Info() << "BlockDownloader statistics:" << std::setfill(' ')
                        << " proc: " << message->name().substr(0, 3) << " | req/skel " << std::setw(2) << std::right
                        << reqs << "/" << std::setw(4) << std::left << header_chain_.statistics_.skeleton_condition
                        << " | queue: " << std::setw(3) << std::right << messages_.size()
                        << " | links: " << std::setw(7) << std::right << header_chain_.pending_links()
                        << " | anchors: " << std::setw(3) << std::right << header_chain_.anchors()
                        << " | db: " << std::setw(10) << std::right << header_chain_.highest_block_in_db()
                        << " | rej: " << std::setw(10) << std::right << rejected_headers;
        }
    }

    stop();
    log::Warning() << "BlockDownloader execution_loop is stopping...";
}

}  // namespace silkworm
