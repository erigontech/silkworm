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

#include "messages/inbound_message.hpp"
#include "messages/outbound_get_block_headers.hpp"
#include "messages/outbound_new_block_hashes.hpp"

namespace silkworm {

HeaderStage::HeaderStage(const Db::ReadWriteAccess& dba, BlockDownloader& bd)
    : db_access_{dba}, block_downloader_(bd) {
}

HeaderStage::~HeaderStage() {
}

auto HeaderStage::forward(bool first_sync) -> Stage::Result {
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
        Db::ReadWriteAccess::Tx tx = db_access_.start_tx();  // start a new tx only if db_access has not an active tx
        PersistedChain persisted_chain(tx);

        if (persisted_chain.unwind_needed()) {
            tx.commit();
            log::Info() << "[1/16 Headers] End (forward skipped due to unwind_needed detection, canonical chain updated), "
                << "duration=" << timing.format(timing.lap_duration());
            log::Trace() << "[INFO] HeaderDownloader forward skipped due to unwind_needed detection, canonical chain updated";
            result.status = Stage::Result::Done;
            return result;
        }

        RepeatedMeasure<BlockNum> height_progress(persisted_chain.initial_height());
        log::Info() << "[1/16 Headers] Waiting for headers... from=" << height_progress.get();

        // sync status
        auto sync_command = sync_working_chain(persisted_chain.initial_height());
        sync_command->result().get();  // blocking

        // prepare headers, if any
        auto withdraw_command = withdraw_stable_headers();

        // header processing
        time_point_t last_update = system_clock::now();
        while (!new_height_reached && !block_downloader_.is_stopping()) {

            // make some outbound header requests
            send_header_requests();

            // check if it needs to persist some headers
            if (withdraw_command->completed_and_read()) {
                // submit another withdrawal command
                withdraw_command = withdraw_stable_headers();
            }
            else if (withdraw_command->result().wait_for(500ms) == std::future_status::ready) {
                // check the result of withdrawal command
                auto [stable_headers, in_sync] = withdraw_command->result().get();  // blocking
                if (!stable_headers.empty()) {
                    if (stable_headers.size() > 100000) {
                        log::Info() << "[1/16 Headers] Inserting headers...";
                    }
                    StopWatch insertion_timing; insertion_timing.start();

                    // persist headers
                    persisted_chain.persist(stable_headers);

                    if (stable_headers.size() > 100000) {
                        log::Info() << "[1/16 Headers] Inserted headers tot=" << stable_headers.size()
                            << " (duration=" << StopWatch::format(insertion_timing.lap_duration()) << "s)";
                    }
                }

                // do announcements
                send_announcements();

                // check if finished
                if (first_sync) {  // if this is the first sync (installation time or run time after a long break)...
                    // ... we want to make sure we insert as many headers as possible
                    new_height_reached = in_sync && persisted_chain.best_header_changed();
                } else { // otherwise, we are working at the tip of the chain so ...
                    // ... we need to react quickly when new headers are coming in
                    new_height_reached = persisted_chain.best_header_changed();
                }
            }

            // show progress
            if (system_clock::now() - last_update > 30s) {
                last_update = system_clock::now();

                height_progress.set(persisted_chain.highest_height());

                log::Info() << "[1/16 Headers] Wrote block headers number=" << height_progress.get() << " (+"
                            << height_progress.delta() << "), " << height_progress.throughput() << " headers/secs";
            }
        }

        result.status = Stage::Result::Done;

        if (persisted_chain.unwind_needed()) {
            result.status = Result::UnwindNeeded;
            result.unwind_point = persisted_chain.unwind_point();
            // no need to set result.bad_block
        }

        auto headers_downloaded = persisted_chain.highest_height() - persisted_chain.initial_height();
        log::Info() << "[1/16 Headers] Downloading completed, wrote " << headers_downloaded << " headers,"
            << " last=" << persisted_chain.highest_height()
            << " duration=" << StopWatch::format(timing.lap_duration());

        log::Info() << "[1/16 Headers] Updating canonical chain";
        persisted_chain.close();

        tx.commit();  // this will commit if the tx was started here

        // todo: do we need a sentry.set_status() here?

        log::Info() << "[1/16 Headers] Done, duration= " << StopWatch::format(timing.lap_duration());
        log::Trace() << "[INFO] HeaderDownloader forward operation completed";

    } catch (const std::exception& e) {
        log::Error() << "[1/16 Headers] Aborted due to exception: " << e.what();
        log::Trace() << "[ERROR] HeaderDownloader forward operation is stopping due to an exception: " << e.what();

        // tx rollback executed automatically if needed
        result.status = Stage::Result::Error;
    }

    return result;
}

auto HeaderStage::unwind_to(BlockNum new_height, Hash bad_block) -> Stage::Result {
    Stage::Result result;

    StopWatch timing; timing.start();
    log::Info() << "[1/16 Headers] Unwind start";
    log::Trace() << "[INFO] HeaderDownloader unwind_needed operation started";

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
        log::Trace() << "[INFO] HeaderDownloader unwind_needed operation completed";

    } catch (const std::exception& e) {
        log::Error() << "[1/16 Headers] Unwind aborted due to exception: " << e.what();
        log::Trace() << "[ERROR] HeaderDownloader unwind_needed operation is stopping due to an exception: " << e.what();

        // tx rollback executed automatically if needed
        result.status = Stage::Result::Error;
    }

    return result;
}

// Request new headers from peers
void HeaderStage::send_header_requests() {
    // if (!sentry_.ready()) return;

    auto message = std::make_shared<OutboundGetBlockHeaders>();

    block_downloader_.accept(message);
}

// New block hash announcements propagation
void HeaderStage::send_announcements() {
    // if (!sentry_.ready()) return;

    auto message = std::make_shared<OutboundNewBlockHashes>();

    block_downloader_.accept(message);
}

auto HeaderStage::sync_working_chain(BlockNum highest_in_db) -> std::shared_ptr<InternalMessage<void>> {
    auto message = std::make_shared<InternalMessage<void>>(
        [highest_in_db](HeaderChain& wc, BodySequence&) { wc.sync_current_state(highest_in_db); });

    block_downloader_.accept(message);

    return message;
}

auto HeaderStage::withdraw_stable_headers() -> std::shared_ptr<InternalMessage<std::tuple<Headers, bool>>> {
    using result_t = std::tuple<Headers, bool>;

    auto message = std::make_shared<InternalMessage<result_t>>([](HeaderChain& wc, BodySequence&) {
        Headers headers = wc.withdraw_stable_headers();
        bool in_sync = wc.in_sync();
        return result_t{std::move(headers), in_sync};
    });

    block_downloader_.accept(message);

    return message;
}

auto HeaderStage::update_bad_headers(std::set<Hash> bad_headers) -> std::shared_ptr<InternalMessage<void>> {
    auto message = std::make_shared<InternalMessage<void>>(
        [bads = std::move(bad_headers)](HeaderChain& wc, BodySequence&) { wc.add_bad_headers(bads); });

    block_downloader_.accept(message);

    return message;
}

}  // namespace silkworm
