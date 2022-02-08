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
#include "header_downloader.hpp"

#include <chrono>
#include <thread>

#include <silkworm/common/log.hpp>

#include "messages/InboundMessage.hpp"
#include "messages/OutboundGetBlockHeaders.hpp"
#include "messages/OutboundNewBlockHashes.hpp"

namespace silkworm {

HeaderDownloader::HeaderDownloader(SentryClient& sentry, const Db::ReadWriteAccess& db_access,
                                   const ChainIdentity& chain_identity)
    : db_access_{db_access}, sentry_{sentry}, working_chain_(consensus::engine_factory(chain_identity.chain)) {
    auto tx = db_access_.start_ro_tx();
    working_chain_.recover_initial_state(tx);
    working_chain_.set_preverified_hashes(&(PreverifiedHashes::per_chain.at(chain_identity.chain.chain_id)));
}

HeaderDownloader::~HeaderDownloader() {
    stop();
    log::Error() << "HeaderDownloader destroyed";
}

void HeaderDownloader::receive_message(const sentry::InboundMessage& raw_message) {
    auto message = InboundBlockAnnouncementMessage::make(raw_message, working_chain_, sentry_);

    SILK_TRACE << "HeaderDownloader received message " << *message;

    messages_.push(message);
}

void HeaderDownloader::execution_loop() {
    using namespace std::chrono_literals;

    sentry_.subscribe(SentryClient::Scope::BlockAnnouncements,
                      [this](const sentry::InboundMessage& msg) { receive_message(msg); });

    while (!is_stopping() && !sentry_.is_stopping()) {
        // pop a message from the queue
        std::shared_ptr<Message> message;
        bool present = messages_.timed_wait_and_pop(message, 1000ms);
        if (!present) continue;  // timeout, needed to check exiting_

        auto in_message = std::dynamic_pointer_cast<InboundMessage>(message);
        if (in_message) {
            SILK_TRACE << "HeaderDownloader processing message " << *in_message;
        }

        // process the message (command pattern)
        message->execute();

        auto out_message = std::dynamic_pointer_cast<OutboundMessage>(message);
        if (out_message) {
            SILK_TRACE << "HeaderDownloader sent message " << *out_message;
        }

    }

    stop();
    log::Warning() << "HeaderDownloader execution_loop is stopping...";
}

auto HeaderDownloader::forward(bool first_sync) -> Stage::Result {
    using std::shared_ptr;
    using namespace std::chrono_literals;

    Stage::Result result;
    bool new_height_reached = false;
    std::thread message_receiving;

    log::Info() << "HeaderDownloader forward operation started";

    try {
        Db::ReadWriteAccess::Tx tx = db_access_.start_tx();  // this will start a new tx only if db_access has not
                                                             // an active tx
        PersistedChain persisted_chain_(tx);

        if (persisted_chain_.unwind_detected()) {
            tx.commit();
            log::Info() << "HeaderDownloader forward operation cannot start due to unwind detection";
            result.status = Stage::Result::Unknown;  // todo: Erigon does not change stage-state here, what can we do?
            return result;
        }

        // sync status
        auto sync_command = sync_working_chain(persisted_chain_.initial_height());
        sync_command->result().get();  // blocking

        // message processing
        time_point_t last_request;
        while (!new_height_reached && !sentry_.is_stopping()) {
            // at every minute...
            if (std::chrono::system_clock::now() - last_request > 60s) {
                last_request = std::chrono::system_clock::now();

                log::Info() << "HeaderDownloader status: " << working_chain_.human_readable_status();

                // make some outbound header requests
                send_header_requests();

                // check if it needs to persist some headers
                auto command = withdraw_stable_headers();
                auto [stable_headers, in_sync] = command->result().get();  // blocking
                persisted_chain_.persist(stable_headers);

                // do announcements
                send_announcements();

                // check if finished - todo: improve clarity
                if (first_sync) {  // first_sync_ = installation time or run time after a long break
                    // if this is the first sync, we want to make sure we insert as many headers as possible
                    new_height_reached = in_sync && persisted_chain_.best_header_changed();
                } else {
                    // if this is not the first sync, we are working at the tip of the chain,
                    // so we need to react quickly when new headers are coming in
                    new_height_reached = persisted_chain_.best_header_changed();
                }

                // todo: log progress - logProgressHeaders(logPrefix, prevProgress, progress)
                log::Info() << "HeaderDownloader status: current persisted height="
                             << persisted_chain_.highest_height();
            } else {
                std::this_thread::sleep_for(1s);
            }
        }

        result.status = Stage::Result::Done;

        // see HeadersForward
        if (persisted_chain_.unwind()) {
            result.status = Result::UnwindNeeded;
            result.unwind_point = persisted_chain_.unwind_point();
        }

        persisted_chain_.close();

        tx.commit();  // this will commit if the tx was started here

        // todo: do we need a sentry.set_status() here?

        log::Info() << "HeaderDownloader forward operation completed";
    } catch (const std::exception& e) {
        log::Error() << "HeaderDownloader forward operation is stopping due to an exception: " << e.what();
        // tx rollback executed automatically if needed
        result.status = Stage::Result::Error;
    }

    return result;
}

auto HeaderDownloader::unwind_to(BlockNum new_height, Hash bad_block) -> Stage::Result {
    Stage::Result result;

    log::Info() << "HeaderDownloader unwind operation started";

    try {
        Db::ReadWriteAccess::Tx tx = db_access_.start_tx();

        std::optional<BlockNum> new_max_block_num;
        std::set<Hash> bad_headers = PersistedChain::remove_headers(new_height, bad_block, new_max_block_num, tx);
        // todo: do we need to save bad_headers in the state and pass old bad headers here?

        if (new_max_block_num.has_value()) {  // happens when bad_block has value
            result.status = Result::DoneAndUpdated;
            result.current_point = new_max_block_num;
        } else {
            result.status = Result::SkipTx;  // todo:  here Erigon does unwind_state.signal(skip_tx), check!
        }

        update_bad_headers(std::move(bad_headers));

        tx.commit();

        // todo: do we need a sentry.set_status() here?

        log::Info() << "HeaderDownloader unwind operation completed";
    } catch (const std::exception& e) {
        log::Error() << "HeaderDownloader unwind operation is stopping due to an exception: " << e.what();
        // tx rollback executed automatically if needed
        result.status = Stage::Result::Error;
    }

    return result;
}

// Request new headers from peers
void HeaderDownloader::send_header_requests() {
    // if (!sentry_.ready()) return;

    auto message = std::make_shared<OutboundGetBlockHeaders>(working_chain_, sentry_);

    SILK_TRACE << "HeaderDownloader sending message " << *message;

    messages_.push(message);
}

// New block hash announcements propagation
void HeaderDownloader::send_announcements() {
    // if (!sentry_.ready()) return;

    auto message = std::make_shared<OutboundNewBlockHashes>(working_chain_, sentry_);

    SILK_TRACE << "HeaderDownloader sending announcements";

    messages_.push(message);
}

auto HeaderDownloader::sync_working_chain(BlockNum highest_in_db) -> std::shared_ptr<InternalMessage<void>> {
    auto message = std::make_shared<InternalMessage<void>>(
        working_chain_, [highest_in_db](WorkingChain& wc) { wc.sync_current_state(highest_in_db); });

    messages_.push(message);

    return message;
}

auto HeaderDownloader::withdraw_stable_headers() -> std::shared_ptr<InternalMessage<std::tuple<Headers, bool>>> {
    using result_t = std::tuple<Headers, bool>;

    auto message = std::make_shared<InternalMessage<result_t>>(working_chain_, [](WorkingChain& wc) {
        Headers headers = wc.withdraw_stable_headers();
        bool in_sync = wc.in_sync();
        return result_t{std::move(headers), in_sync};
    });

    messages_.push(message);

    return message;
}

auto HeaderDownloader::update_bad_headers(std::set<Hash> bad_headers) -> std::shared_ptr<InternalMessage<void>> {
    auto message = std::make_shared<InternalMessage<void>>(
        working_chain_, [bads = std::move(bad_headers)](WorkingChain& wc) { wc.add_bad_headers(bads); });

    messages_.push(message);

    return message;
}

}  // namespace silkworm
