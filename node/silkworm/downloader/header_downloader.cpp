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
#include <silkworm/common/measure.hpp>
#include <silkworm/common/stopwatch.hpp>

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
    using namespace std::chrono;
    using namespace std::chrono_literals;

    sentry_.subscribe(SentryClient::Scope::BlockAnnouncements,
                      [this](const sentry::InboundMessage& msg) { receive_message(msg); });

    time_point_t last_update = system_clock::now();

    while (!is_stopping() && !sentry_.is_stopping()) {
        // pop a message from the queue
        std::shared_ptr<Message> message;
        bool present = messages_.timed_wait_and_pop(message, 1000ms);
        if (!present) continue;  // timeout, needed to check exiting_

        // process the message (command pattern)
        message->execute();

        // log status
        if (silkworm::log::test_verbosity(silkworm::log::Level::kTrace)) {
            auto out_message = std::dynamic_pointer_cast<OutboundGetBlockHeaders>(message);
            auto req_set = out_message != nullptr ? out_message->sent_request() : 0;
            uint64_t rejected_headers =
                working_chain_.statistics_.received_headers - working_chain_.statistics_.accepted_headers;
            log::Info() << "HeaderDownloader statistics:" << std::setfill(' ')
                << " proc: " << message->name().substr(0, 3) << " | req/skel " << std::setw(2) << std::right
                << req_set << "/" << std::setw(4) << std::left << working_chain_.statistics_.skeleton_condition
                << " | queue: " << std::setw(3) << std::right << messages_.size()
                << " | links: " << std::setw(7) << std::right << working_chain_.pending_links()
                << " | anchors: " << std::setw(3) << std::right << working_chain_.anchors()
                << " | db: " << std::setw(10) << std::right << working_chain_.highest_block_in_db()
                << " | rej: " << std::setw(10) << std::right << rejected_headers;
        }

        if (system_clock::now() - last_update > 30s) {
            last_update = system_clock::now();
            log::Info() << "HeaderDownloader statistics: "
                << messages_.size() << " waiting-msg, "
                << working_chain_.pending_links() << " links, "
                << working_chain_.anchors() << " anchors "
                << "/bn db=" << working_chain_.highest_block_in_db() << ", "
                << "tip=" << working_chain_.top_seen_block_height() << " "
                << "/" << working_chain_.statistics_;
        }
    }

    stop();
    log::Warning() << "HeaderDownloader execution_loop is stopping...";
}

auto HeaderDownloader::forward(bool first_sync) -> Stage::Result {
    using std::shared_ptr;
    using namespace std::chrono_literals;
    using namespace std::chrono;

    Stage::Result result;
    bool new_height_reached = false;
    std::thread message_receiving;

    StopWatch timing; timing.start();
    log::Info() << "[1/16 Headers] Start";
    log::Trace() << "[INFO] HeaderDownloader forward operation started";

    try {
        Db::ReadWriteAccess::Tx tx = db_access_.start_tx();  // this will start a new tx only if db_access has not
                                                             // an active tx
        PersistedChain persisted_chain_(tx);

        if (persisted_chain_.unwind_detected()) {
            tx.commit();
            log::Info() << "[1/16 Headers] End (not started due to unwind detection), duration= "
                        << timing.format(timing.lap_duration());
            log::Trace() << "[INFO] HeaderDownloader forward operation cannot start due to unwind detection";
            result.status = Stage::Result::Unknown;
            return result;
        }

        RepeatedMeasure<BlockNum> height_progress(persisted_chain_.initial_height());
        log::Info() << "[1/16 Headers] Waiting for headers... from=" << height_progress.get();

        // sync status
        auto sync_command = sync_working_chain(persisted_chain_.initial_height());
        sync_command->result().get();  // blocking

        // prepare headers, if any
        auto withdraw_command = withdraw_stable_headers();
        auto withdraw_result = withdraw_command->result();

        // message processing
        time_point_t last_update = system_clock::now();
        while (!new_height_reached && !sentry_.is_stopping()) {

            // make some outbound header requests
            send_header_requests();

            // check if it needs to persist some headers
            if (withdraw_result.wait_for(500ms) == std::future_status::ready) {

                auto [stable_headers, in_sync] = withdraw_result.get();  // blocking
                if (!stable_headers.empty()) {
                    if (stable_headers.size() > 10000)
                        log::Info() << "[1/16 Headers] Inserting headers...";
                    StopWatch insertion_timing; insertion_timing.start();

                    // persist headers
                    persisted_chain_.persist(stable_headers);

                    log::Info() << "[1/16 Headers] Inserted headers tot=" << stable_headers.size()
                        << " (duration= " << StopWatch::format(insertion_timing.lap_duration()) << "s)";
                }

                // submit another command
                withdraw_command = withdraw_stable_headers();
                withdraw_result = withdraw_command->result();

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
            }

            // show progress
            if (system_clock::now() - last_update > 30s) {
                last_update = system_clock::now();

                height_progress.set(persisted_chain_.highest_height());

                log::Info() << "[1/16 Headers] Wrote block headers number=" << height_progress.get() << " (+"
                            << height_progress.delta() << "), " << height_progress.throughput() << " headers/secs";
            }
        }

        result.status = Stage::Result::Done;

        // see HeadersForward
        if (persisted_chain_.unwind()) {
            result.status = Result::UnwindNeeded;
            result.unwind_point = persisted_chain_.unwind_point();
        }

        log::Info() << "[1/16 Headers] Download completed, duration= " << StopWatch::format(timing.lap_duration());
        log::Info() << "[1/16 Headers] Updating canonical chain";
        persisted_chain_.close();

        tx.commit();  // this will commit if the tx was started here

        // todo: do we need a sentry.set_status() here?

        log::Info() << "[1/16 Headers] Completed, duration= " << StopWatch::format(timing.lap_duration());
        log::Trace() << "[INFO] HeaderDownloader forward operation completed";

    } catch (const std::exception& e) {
        log::Error() << "[1/16 Headers] Aborted due to exception";
        log::Trace() << "[ERROR] HeaderDownloader forward operation is stopping due to an exception: " << e.what();

        // tx rollback executed automatically if needed
        result.status = Stage::Result::Error;
    }

    return result;
}

auto HeaderDownloader::unwind_to(BlockNum new_height, Hash bad_block) -> Stage::Result {
    Stage::Result result;

    StopWatch timing; timing.start();
    log::Info() << "[1/16 Headers] Unwind start";
    log::Trace() << "[INFO] HeaderDownloader unwind operation started";

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

        log::Info() << "[1/16 Headers] Unwind completed, duration= " << StopWatch::format(timing.lap_duration());
        log::Trace() << "[INFO] HeaderDownloader unwind operation completed";

    } catch (const std::exception& e) {
        log::Error() << "[1/16 Headers] Unwind aborted due to exception";
        log::Trace() << "[ERROR] HeaderDownloader unwind operation is stopping due to an exception: " << e.what();

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
