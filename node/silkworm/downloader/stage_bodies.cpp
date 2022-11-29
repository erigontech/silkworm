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

#include "stage_bodies.hpp"

#include <chrono>
#include <thread>

#include "silkworm/common/log.hpp"
#include "silkworm/common/measure.hpp"
#include "silkworm/common/stopwatch.hpp"
#include "silkworm/db/stages.hpp"
#include "silkworm/downloader/messages/outbound_get_block_bodies.hpp"
#include "silkworm/downloader/messages/outbound_new_block.hpp"

namespace silkworm::chainsync {

BodiesStage::BodiesStage(BlockExchange& bd, stagedsync::ExecutionEngine& ee)
    : Stage("consensus-bodies"), block_downloader_{bd}, exec_engine_{ee}, log_prefix_{"[Cons.Bodies]"} {
}

BodiesStage::~BodiesStage() {
}

auto BodiesStage::forward(std::optional<NewHeight> new_height) -> NewHeight {
    using std::shared_ptr;
    using namespace std::chrono_literals;
    using namespace std::chrono;

    if (!new_height.has_value()) {
        throw std::logic_error("Consensus bodies stages need a target height");
    }

    auto constexpr KShortInterval = 200ms;
    auto constexpr kProgressUpdateInterval = 30s;

    StopWatch timing;
    timing.start();
    log::Info(log_prefix_) << "Start";

    try {
        BlockIdPair initial_head{};
        std::tie(initial_head.number, initial_head.hash) = exec_engine_.get_bodies_head();

        current_height_ = initial_head.number;
        get_log_progress();  // this is a trick to set log progress initial value, please improve

        if (block_downloader_.is_stopping()) {
            log::Error(log_prefix_) << "Aborted, block exchange is down";
            return NewHeight{.block_num = initial_head.number, .hash = initial_head.hash};
        }

        RepeatedMeasure<BlockNum> height_progress(initial_head.number);
        log::Info(log_prefix_) << "Waiting for bodies... from=" << height_progress.get();

        // sync status
        BlockNum target_height = new_height->block_num;
        auto sync_command = sync_body_sequence(initial_head.number, target_height);  // todo check if target_height is ok in place of headers height #######
        sync_command->result().get();                                                // blocking

        // prepare bodies, if any
        auto withdraw_command = withdraw_ready_bodies();

        // block processing
        BlockIdPair current_head = initial_head;

        time_point_t last_update = system_clock::now();
        while (current_head.number < target_height && !is_stopping()) {
            send_body_requests();

            if (withdraw_command->completed_and_read()) {
                // renew request
                withdraw_command = withdraw_ready_bodies();
            } else if (withdraw_command->result().wait_for(KShortInterval) == std::future_status::ready) {
                // read response
                auto bodies = withdraw_command->result().get();

                // send bodies
                exec_engine_.insert_bodies(bodies);

                // compute new head
                auto highest_block = std::max_element(bodies.begin(), bodies.end(), [](shared_ptr<Block>& a, shared_ptr<Block>& b) {
                    return a->header.number < b->header.number;
                });
                if (highest_block->get()->header.number > current_head.number) {
                    current_head = {.number = highest_block->get()->header.number, .hash = highest_block->get()->header.hash()};
                }

                // do announcements
                send_announcements();
            }

            // show progress
            if (system_clock::now() - last_update > kProgressUpdateInterval) {
                last_update = system_clock::now();

                height_progress.set(current_head.number);

                log::Debug(log_prefix_) << "Wrote block bodies number=" << height_progress.get()
                                        << " (+" << height_progress.delta() << "), "
                                        << height_progress.throughput() << " bodies/secs";
            }
        }

        auto bodies_downloaded = current_head.number - initial_head.number;
        log::Info(log_prefix_) << "Downloading completed, wrote " << bodies_downloaded << " bodies,"
                               << " last=" << current_head.number
                               << " duration=" << StopWatch::format(timing.lap_duration());

        log::Info(log_prefix_) << "Done, duration= " << StopWatch::format(timing.lap_duration());

        return NewHeight{.block_num = current_head.number, .hash = current_head.hash};

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Aborted due to exception: " << e.what();
        throw e;
    }
}

void BodiesStage::unwind(UnwindPoint unwind_point) {
    current_height_ = unwind_point.block_num;
}

void BodiesStage::send_body_requests() {
    auto message = std::make_shared<OutboundGetBlockBodies>();

    block_downloader_.accept(message);
}

auto BodiesStage::sync_body_sequence(BlockNum highest_body, BlockNum highest_header)
    -> std::shared_ptr<InternalMessage<void>> {
    auto message = std::make_shared<InternalMessage<void>>(
        [highest_body, highest_header](HeaderChain&, BodySequence& bs) {
            bs.sync_current_state(highest_body, highest_header);
        });

    block_downloader_.accept(message);

    return message;
}

auto BodiesStage::withdraw_ready_bodies() -> std::shared_ptr<InternalMessage<std::vector<std::shared_ptr<Block>>>> {
    using result_t = std::vector<std::shared_ptr<Block>>;

    auto message = std::make_shared<InternalMessage<result_t>>([](HeaderChain&, BodySequence& bs) {
        return bs.withdraw_ready_bodies();
    });

    block_downloader_.accept(message);

    return message;
}

// New block announcements propagation
void BodiesStage::send_announcements() {
    auto message = std::make_shared<OutboundNewBlock>();

    block_downloader_.accept(message);
}

std::vector<std::string> BodiesStage::get_log_progress() {  // implementation MUST be thread safe
    static RepeatedMeasure<BlockNum> height_progress{0};

    height_progress.set(current_height_);
    auto peers = block_downloader_.sentry().active_peers();

    return {"current number", std::to_string(height_progress.get()),
            "progress", std::to_string(height_progress.delta()),
            "bodies/secs", std::to_string(height_progress.throughput()),
            "peers", std::to_string(peers)};
}

}  // namespace silkworm::chainsync
