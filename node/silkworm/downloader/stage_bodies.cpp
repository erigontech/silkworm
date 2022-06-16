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

#include "stage_bodies.hpp"

#include <chrono>
#include <thread>

#include <silkworm/common/log.hpp>
#include <silkworm/common/measure.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/downloader/messages/outbound_get_block_bodies.hpp>
#include <silkworm/downloader/messages/outbound_new_block.hpp>
#include <silkworm/downloader/internals/body_persistence.hpp>

namespace silkworm {

/*
    Erigon block downloader pseudo-code
    -----------------------------------

    Data structures
    ---------------
    requests:         map offset → bodies_request
    deliveriesB:      map offset → body
    deliveriesH:      map offset → header
    requestedMap:     map hash(txes)+hash(uncles) → blockNum
    delivered:        set blockNum
    prefetchedBlocks: rlu-map hash → block
    peerMap:          map peer-id → #penalizations


    BodiesForward()
    ---------------
    1. UpdateStatusFromDb
    2. Loop
       2.1 for more times
          2.1.1 req = RequestMoreBodies()
          2.1.2 send_message_by_min_block(req)
       2.2 headers, bodies = GetDeliveries()
       2.3 for each (header, body)
          2.3.1 verify(body) [requires headers from db]
          2.3.2 write_to_db(body)
       2.4 update_progress

    RequestMoreBodies()
    -------------------
    1. headerProgress <-- db
    2. bodyProgress <-- StageState (=stage loop?)
    3. delivered = roaring64.Bitmap<blockNum>
    4. requests = map<offset -> bodies_request>
    5. newRequest = BodyRequest
    6. for blockNum = min(requested), while newRequest.len() < max, blockNum++
       6.0 index = blockNum - min(requested)
       6.1 if delivered.contains(blockNum) continue
       6.2 request_made = requests.contains(offset)
       6.3 if request_made
          6.3.1 if not timeout continue
          6.3.2 else delete request_made from requests, increment peer penalties
       6.4 header = get_from_deliveries_h_b() or get_from_cache() or get_from_canonical_table(blockNum)
       6.5 add header to deliveries_h
       6.6 if block in cache/db
          6.6.1 add block to deliveries_b,
          6.6.2 to_request <-- false
          6.6.3 delivered.add(blockNum)
       6.7 else
          6.7.1 to_request <-- true
          6.7.2 newRequest.blockNums.append(blockNum)
          6.7.3 newRequest.hashes.append(hash)
          6.7.4 requests.add(blockNum → newRequest)
          6.7.5 requestMap.add(hash(txes)+hash(uncles) → blockNum)

    GetDeliveries()
    ---------------
    1. for body in received_bodies
       1.1 if requestedMap[hash(txes)+hash(uncles)] == false
          1.1.1 continue
       1.2 else
          1.2.1 clear requestedMap & requests[offset]
          1.2.2 deliveriesB.add(offset → body)
          1.2.3 delivered.add(blockNum)
    2. headers,bodies = lowest_contiguous_sequence(deliveriesH,deliveriesB)
    3. remove (headers,bodies) from (deliveriesH,deliveriesB)
    4. returns (headers,bodies)

 */
BodiesStage::BodiesStage(const Db::ReadWriteAccess& db_access, BlockExchange& bd)
    : db_access_{db_access}, block_downloader_{bd} {
}

BodiesStage::~BodiesStage() {
    // todo: implement
}

Stage::Result BodiesStage::forward([[maybe_unused]] bool first_sync) {
    using std::shared_ptr;
    using namespace std::chrono_literals;
    using namespace std::chrono;

    Stage::Result result;

    auto constexpr KShortInterval = 200ms;
    auto constexpr kProgressUpdateInterval = 30s;

    StopWatch timing; timing.start();
    log::Info() << "[2/16 Bodies] Start";

    try {
        Db::ReadWriteAccess::Tx tx = db_access_.start_tx();  // start a new tx only if db_access has not an active tx

        BodyPersistence body_persistence(tx, block_downloader_.chain_identity());

        RepeatedMeasure<BlockNum> height_progress(body_persistence.initial_height());
        log::Info() << "[2/16 Bodies] Waiting for bodies... from=" << height_progress.get();

        // sync status
        BlockNum headers_stage_height = tx.read_stage_progress(db::stages::kHeadersKey);
        auto sync_command = sync_body_sequence(body_persistence.initial_height(), headers_stage_height);
        sync_command->result().get();  // blocking

        // prepare bodies, if any
        auto withdraw_command = withdraw_ready_bodies();

        // block processing
        time_point_t last_update = system_clock::now();
        while (body_persistence.highest_height() < headers_stage_height && !block_downloader_.is_stopping()) {

            send_body_requests();

            if (withdraw_command->completed_and_read()) {
                // renew request
                withdraw_command = withdraw_ready_bodies();
            }
            else if (withdraw_command->result().wait_for(KShortInterval) == std::future_status::ready) {
                // read response
                auto bodies = withdraw_command->result().get();
                // persist bodies
                body_persistence.persist(bodies);
                // check unwind condition
                if (body_persistence.unwind_needed()) {
                    result.status = Result::UnwindNeeded;
                    result.unwind_point = body_persistence.unwind_point();
                    break;
                } else {
                    result.status = Stage::Result::Done;
                }

                // do announcements
                send_announcements();
            }

            // show progress
            if (system_clock::now() - last_update > kProgressUpdateInterval) {
                last_update = system_clock::now();

                height_progress.set(body_persistence.highest_height());

                log::Info() << "[2/16 Bodies] Wrote block bodies number=" << height_progress.get() << " (+"
                            << height_progress.delta() << "), " << height_progress.throughput() << " bodies/secs";
            }
        }

        auto bodies_downloaded = body_persistence.highest_height() - body_persistence.initial_height();
        log::Info() << "[2/16 Bodies] Downloading completed, wrote " << bodies_downloaded << " bodies,"
                    << " last=" << body_persistence.highest_height()
                    << " duration=" << StopWatch::format(timing.lap_duration());

        body_persistence.close();

        tx.commit();  // this will commit if the tx was started here

        log::Info() << "[2/16 Bodies] Done, duration= " << StopWatch::format(timing.lap_duration());

    } catch (const std::exception& e) {
        log::Error() << "[2/16 Bodies] Aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result.status = Stage::Result::Error;
    }

    return result;
}

Stage::Result BodiesStage::unwind_to(BlockNum new_height, Hash bad_block) {
    Stage::Result result;

    StopWatch timing; timing.start();
    log::Info() << "[2/16 Bodies] Unwind start";

    try {
        Db::ReadWriteAccess::Tx tx = db_access_.start_tx();

        BodyPersistence::remove_bodies(new_height, bad_block, tx);

        tx.commit();

        log::Info() << "[1/16 Bodies] Unwind completed, duration= " << StopWatch::format(timing.lap_duration());

    } catch (const std::exception& e) {
        log::Error() << "[1/16 Bodies] Unwind aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result.status = Stage::Result::Error;
    }

    return result;
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

}  // namespace silkworm
