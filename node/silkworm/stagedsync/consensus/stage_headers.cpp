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
#include "stage_headers.hpp"

#include <chrono>
#include <thread>

#include <silkworm/common/log.hpp>
#include <silkworm/common/as_range.hpp>
#include <silkworm/common/measure.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/downloader/internals/header_chain.hpp>
#include <silkworm/downloader/messages/inbound_message.hpp>
#include <silkworm/downloader/messages/outbound_get_block_headers.hpp>
#include <silkworm/downloader/messages/outbound_new_block_hashes.hpp>

#include "chain_fork_view.hpp"

namespace silkworm::stagedsync::consensus {

HeadersStage::HeadersStage(BlockExchange& bd, ExecutionEngine& ee)
    : Stage(db::stages::kHeadersKey), block_downloader_(bd), exec_engine_{ee}, log_prefix_{"[Cons.Headers]"}
{
    // User can specify to stop downloading process at some block
    const auto stop_at_block = stop_at_block_from_env();
    if (stop_at_block.has_value()) {
        target_block_ = stop_at_block;
        log::Info(log_prefix_) << "env var STOP_AT_BLOCK set, target block=" << target_block_.value();
    }
}

HeadersStage::~HeadersStage() {
}

auto HeadersStage::forward(std::optional<NewHeight> desired_height) -> NewHeight {
    using std::shared_ptr;
    using namespace std::chrono_literals;
    using namespace std::chrono;
    using std::tie;

    if (desired_height.has_value()) throw std::logic_error("consensus headers stage currently doesn't support target height");

    bool new_height_reached = false;
    std::thread message_receiving;

    StopWatch timing;
    timing.start();
    log::Info(log_prefix_) << "Start";

    try {
        ChainForkView chain_fork_view{exec_engine_};

        //auto [initial_height, initial_hash, initial_td] = exec_engine_.get_headers_head();
        auto initial_height = chain_fork_view.head_height();
        auto initial_hash = chain_fork_view.head_hash();

        current_height_ = initial_height;
        get_log_progress();  // this is a trick to set log progress initial value, please improve

        if (target_block_ && current_height_ >= *target_block_) {
            log::Info(log_prefix_) << "End, forward skipped due to target block (" << *target_block_ << ") reached";
            return NewHeight{.block_num = current_height_, .hash = initial_hash};
        }

        if (block_downloader_.is_stopping()) {
            log::Error(log_prefix_) << "Aborted, block exchange is down";
            return NewHeight{.block_num = initial_height, .hash = initial_hash};
        }

        RepeatedMeasure<BlockNum> height_progress(initial_height);
        log::Info(log_prefix_) << "Waiting for headers... from=" << height_progress.get();

        // sync status
        auto sync_command = sync_header_chain(initial_height);
        sync_command->result().get();  // blocking

        // prepare headers, if any
        auto withdraw_command = withdraw_stable_headers();

        // header processing
        time_point_t last_update = system_clock::now();
        while (!new_height_reached && !is_stopping()) {
            // make some outbound header requests
            send_header_requests();

            // check if it needs to persist some headers
            if (withdraw_command->completed_and_read()) {
                // submit another withdrawal command
                withdraw_command = withdraw_stable_headers();
            } else if (withdraw_command->result().wait_for(500ms) == std::future_status::ready) {
                // check the result of withdrawal command
                auto [stable_headers, in_sync] = withdraw_command->result().get();  // blocking
                if (!stable_headers.empty()) {
                    if (stable_headers.size() > 100000) {
                        log::Info(log_prefix_) << "Inserting headers...";
                    }
                    StopWatch insertion_timing;
                    insertion_timing.start();

                    // core activities
                    as_range::for_each(stable_headers, [&chain_fork_view](const auto& header) { chain_fork_view.add(*header); });
                    exec_engine_.insert_headers(stable_headers);

                    current_height_ = chain_fork_view.head_height();

                    if (stable_headers.size() > 100000) {
                        log::Info(log_prefix_) << "Inserted headers tot=" << stable_headers.size()
                                               << " (duration=" << StopWatch::format(insertion_timing.lap_duration()) << "s)";
                    }
                }

                // do announcements
                send_announcements();

                // check if finished
                if (is_first_cycle_) {  // if this is the first sync (first run or run after a long break)...
                    // ... we want to make sure we insert as many headers as possible
                    new_height_reached = in_sync && chain_fork_view.head_changed();
                } else {  // otherwise, we are working at the tip of the chain so ...
                    // ... we need to react quickly when new headers are coming in
                    new_height_reached = chain_fork_view.head_changed();
                }
            }

            // show progress
            if (system_clock::now() - last_update > 30s) {
                last_update = system_clock::now();

                height_progress.set(chain_fork_view.head_height());

                log::Debug(log_prefix_) << "Wrote block headers number=" << height_progress.get()
                                        << " (+" << height_progress.delta() << "), "
                                        << height_progress.throughput() << " headers/secs";
            }
        }

        auto headers_downloaded = chain_fork_view.head_height() - initial_height;
        log::Info(log_prefix_) << "Downloading completed, wrote " << headers_downloaded << " headers,"
                               << " last=" << chain_fork_view.head_height()
                               << " duration=" << StopWatch::format(timing.lap_duration());

        log::Info(log_prefix_) << "Updating canonical chain";

        // todo: do we need a sentry.set_status() here?

        NewHeight result{.block_num = chain_fork_view.head_height(), .hash = chain_fork_view.head_hash()};

        log::Info(log_prefix_) << "Done, duration= " << StopWatch::format(timing.lap_duration());
        return result;

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Aborted due to exception: " << e.what();
        throw e;
    }

}

void HeadersStage::unwind(UnwindPoint unwind_point) {
    current_height_ = unwind_point.block_num;
}

// Request new headers from peers
void HeadersStage::send_header_requests() {
    // if (!sentry_.ready()) return;

    auto message = std::make_shared<OutboundGetBlockHeaders>();

    block_downloader_.accept(message);
}

// New block hash announcements propagation
void HeadersStage::send_announcements() {
    // if (!sentry_.ready()) return;

    auto message = std::make_shared<OutboundNewBlockHashes>();

    block_downloader_.accept(message);
}

auto HeadersStage::sync_header_chain(BlockNum highest_in_db) -> std::shared_ptr<InternalMessage<void>> {
    auto message = std::make_shared<InternalMessage<void>>(
        [highest_in_db](HeaderChain& wc, BodySequence&) { wc.sync_current_state(highest_in_db); });

    block_downloader_.accept(message);

    return message;
}

auto HeadersStage::withdraw_stable_headers() -> std::shared_ptr<InternalMessage<std::tuple<Headers, bool>>> {
    using result_t = std::tuple<Headers, bool>;

    auto message = std::make_shared<InternalMessage<result_t>>([](HeaderChain& wc, BodySequence&) {
        Headers headers = wc.withdraw_stable_headers();
        bool in_sync = wc.in_sync();
        return result_t{std::move(headers), in_sync};
    });

    block_downloader_.accept(message);

    return message;
}

std::vector<std::string> HeadersStage::get_log_progress() {  // implementation MUST be thread safe
    static RepeatedMeasure<BlockNum> height_progress{0};

    height_progress.set(current_height_);
    auto peers = block_downloader_.sentry().active_peers();

    return {"current number", std::to_string(height_progress.get()),
            "progress", std::to_string(height_progress.delta()),
            "headers/secs", std::to_string(height_progress.throughput()),
            "peers", std::to_string(peers)};
}

}  // namespace silkworm::stagedsync
