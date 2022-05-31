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
#include <silkworm/downloader/messages/outbound_get_block_bodies.hpp>

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
    log::set_thread_name("block-exchange");

    sentry_.subscribe(SentryClient::Scope::BlockAnnouncements,
                      [this](const sentry::InboundMessage& msg) { receive_message(msg); });
    sentry_.subscribe(SentryClient::Scope::BlockRequests,
                      [this](const sentry::InboundMessage& msg) { receive_message(msg); });

    auto constexpr kShortInterval = 100ms;
    time_point_t last_update = system_clock::now();

    while (!is_stopping() && !sentry_.is_stopping()) {
        // pop a message from the queue
        std::shared_ptr<Message> message;
        bool present = messages_.timed_wait_and_pop(message, kShortInterval);

        // process the message (command pattern)
        if (present) {
            message->execute(db_access_, header_chain_, body_sequence_, sentry_);
        }

        auto now = system_clock::now();

        // request headers: to do

        // request bodies
        if (body_sequence_.has_bodies_to_request(now)) {
            auto request_message = std::make_shared<OutboundGetBlockBodies>();
            request_message->execute(db_access_, header_chain_, body_sequence_, sentry_);
        }

        // log status
        if (silkworm::log::test_verbosity(silkworm::log::Level::kDebug) && now - last_update > 60s) {
            log_status();
            last_update = now;
        }

    }

    stop();
    log::Warning() << "BlockExchange execution_loop is stopping...";
}

void BlockExchange::log_status() {
    log::Debug() << "BlockExchange messages: " << std::setfill('_') << std::setw(5) << std::right
                 << messages_.size() << " in queue";

    auto [min_anchor_height, max_anchor_height] = header_chain_.anchor_height_range();
    log::Debug() << "BlockExchange headers: " << std::setfill('_')
                 << "links= " << std::setw(7) << std::right << header_chain_.pending_links()
                 << ", anchors= " << std::setw(3) << std::right << header_chain_.anchors()
                 << ", db-height= " << std::setw(10) << std::right << header_chain_.highest_block_in_db()
                 << ", mem-height= " << std::setw(10) << std::right << min_anchor_height
                 << "~" << std::setw(10) << std::right << max_anchor_height
                 << ", net-height= " << std::setw(10) << std::right << header_chain_.top_seen_block_height()
                 << "; stats: " << header_chain_.statistics();

    log::Debug() << "BlockExchange bodies:  " << std::setfill('_')
                 << "outstanding bodies= " << std::setw(6) << std::right
                 << body_sequence_.outstanding_bodies(std::chrono::system_clock::now()) << "  "
                 << ", db-height= " << std::setw(10) << std::right << body_sequence_.highest_block_in_db()
                 << ", mem-height= " << std::setw(10) << std::right << body_sequence_.lowest_block_in_memory()
                 << "~" << std::setw(10) << std::right << body_sequence_.highest_block_in_memory()
                 << ", net-height= " << std::setw(10) << std::right << body_sequence_.target_height()
                 << "; stats: " << body_sequence_.statistics();
}

}  // namespace silkworm
