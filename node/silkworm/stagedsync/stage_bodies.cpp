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
#include "silkworm/downloader/internals/body_persistence.hpp"
#include "silkworm/downloader/messages/outbound_get_block_bodies.hpp"
#include "silkworm/downloader/messages/outbound_new_block.hpp"

namespace silkworm::stagedsync {

BodiesStage::BodiesStage(SyncContext* sc, BlockExchange& bd, NodeSettings* ns)
    : Stage(sc, db::stages::kBlockBodiesKey, ns), block_downloader_{bd} {
}

BodiesStage::~BodiesStage() {
}

Stage::Result BodiesStage::forward(db::RWTxn& tx) {
    using std::shared_ptr;
    using namespace std::chrono_literals;
    using namespace std::chrono;

    Stage::Result result = Stage::Result::kUnspecified;
    operation_ = OperationType::Forward;

    auto constexpr KShortInterval = 200ms;
    auto constexpr kProgressUpdateInterval = 30s;

    StopWatch timing;
    timing.start();
    log::Info(log_prefix_) << "Start";

    if (block_downloader_.is_stopping()) {
        log::Error(log_prefix_) << "Aborted, block exchange is down";
        return Stage::Result::kAborted;
    }

    try {
        BodyPersistence body_persistence(tx, block_downloader_.chain_config());
        body_persistence.set_preverified_height(block_downloader_.preverified_hashes().height);

        current_height_ = body_persistence.initial_height();
        get_log_progress();  // this is a trick to set log progress initial value, please improve

        RepeatedMeasure<BlockNum> height_progress(body_persistence.initial_height());
        log::Info(log_prefix_) << "Waiting for bodies... from=" << height_progress.get();

        // sync status
        BlockNum headers_stage_height = db::stages::read_stage_progress(tx, db::stages::kHeadersKey);
        auto sync_command = sync_body_sequence(body_persistence.initial_height(), headers_stage_height);
        sync_command->result().get();  // blocking

        // prepare bodies, if any
        auto withdraw_command = withdraw_ready_bodies();

        // block processing
        time_point_t last_update = system_clock::now();
        while (body_persistence.highest_height() < headers_stage_height && !is_stopping()) {
            send_body_requests();

            if (withdraw_command->completed_and_read()) {
                // renew request
                withdraw_command = withdraw_ready_bodies();
            } else if (withdraw_command->result().wait_for(KShortInterval) == std::future_status::ready) {
                // read response
                auto bodies = withdraw_command->result().get();
                // persist bodies
                body_persistence.persist(bodies);
                current_height_ = body_persistence.highest_height();

                // check unwind condition
                if (body_persistence.unwind_needed()) {
                    result = Stage::Result::kInvalidBlock;
                    sync_context_->unwind_point = body_persistence.unwind_point();
                    break;
                } else {
                    result = Stage::Result::kSuccess;
                }

                // do announcements
                send_announcements();
            }

            // show progress
            if (system_clock::now() - last_update > kProgressUpdateInterval) {
                last_update = system_clock::now();

                height_progress.set(body_persistence.highest_height());

                log::Debug(log_prefix_) << "Wrote block bodies number=" << height_progress.get()
                                        << " (+" << height_progress.delta() << "), "
                                        << height_progress.throughput() << " bodies/secs";
            }
        }

        auto bodies_downloaded = body_persistence.highest_height() - body_persistence.initial_height();
        log::Info(log_prefix_) << "Downloading completed, wrote " << bodies_downloaded << " bodies,"
                               << " last=" << body_persistence.highest_height()
                               << " duration=" << StopWatch::format(timing.lap_duration());

        body_persistence.close();

        tx.commit();  // this will commit if the tx was started here

        log::Info(log_prefix_) << "Done, duration= " << StopWatch::format(timing.lap_duration());

        if (result == Stage::Result::kUnspecified) {
            result = Stage::Result::kSuccess;
        }

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result = Stage::Result::kUnexpectedError;
    }

    return result;
}

Stage::Result BodiesStage::unwind(db::RWTxn& tx) {
    Stage::Result result{Stage::Result::kSuccess};
    operation_ = OperationType::Unwind;

    StopWatch timing;
    timing.start();
    log::Info(log_prefix_) << "Unwind start";

    current_height_ = db::stages::read_stage_progress(tx, db::stages::kBlockBodiesKey);
    get_log_progress();  // this is a trick to set log progress initial value, please improve

    if (!sync_context_->unwind_point.has_value()) {
        operation_ = OperationType::None;
        return result;
    }
    auto new_height = sync_context_->unwind_point.value();

    try {
        BodyPersistence::remove_bodies(new_height, sync_context_->bad_block_hash, tx);

        current_height_ = new_height;

        tx.commit();

        log::Info(log_prefix_) << "Unwind completed, duration= " << StopWatch::format(timing.lap_duration());

        result = Stage::Result::kSuccess;

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Unwind aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result = Stage::Result::kUnexpectedError;
    }

    return result;
}

auto BodiesStage::prune(db::RWTxn&) -> Stage::Result {
    return Stage::Result::kSuccess;
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

auto BodiesStage::withdraw_ready_bodies() -> std::shared_ptr<InternalMessage<std::vector<Block>>> {
    using result_t = std::vector<Block>;

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

}  // namespace silkworm::stagedsync
