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

#include "block_exchange.hpp"

#include <chrono>

#include <boost/signals2.hpp>

#include <silkworm/core/common/random_number.hpp>
#include <silkworm/core/common/singleton.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/common/preverified_hashes.hpp>
#include <silkworm/sync/messages/inbound_message.hpp>
#include <silkworm/sync/messages/internal_message.hpp>
#include <silkworm/sync/sentry_client.hpp>

namespace silkworm {

BlockExchange::BlockExchange(SentryClient& sentry, const db::ROAccess& dba, const ChainConfig& chain_config)
    : db_access_{dba},
      sentry_{sentry},
      chain_config_{chain_config},
      header_chain_{chain_config},
      body_sequence_{} {
}

BlockExchange::~BlockExchange() {
    BlockExchange::stop();
}

const ChainConfig& BlockExchange::chain_config() const { return chain_config_; }

SentryClient& BlockExchange::sentry() const { return sentry_; }
BlockExchange::ResultQueue& BlockExchange::result_queue() { return results_; }
bool BlockExchange::in_sync() const { return in_sync_; }
BlockNum BlockExchange::current_height() const { return current_height_; }

void BlockExchange::accept(std::shared_ptr<Message> message) {
    statistics_.internal_msgs++;
    messages_.push(std::move(message));
}

void BlockExchange::receive_message(std::shared_ptr<InboundMessage> message) {
    statistics_.received_msgs++;

    // SILK_TRACE << "BlockExchange received message " << *message;

    messages_.push(std::move(message));
}

void BlockExchange::execution_loop() {
    using namespace std::chrono;
    using namespace std::chrono_literals;

    auto announcement_receiving_callback = [this](std::shared_ptr<InboundMessage> msg) {
        statistics_.nonsolic_msgs++;
        receive_message(std::move(msg));
    };
    auto response_receiving_callback = [this](std::shared_ptr<InboundMessage> msg) {
        receive_message(std::move(msg));
    };
    auto sentry_received_message_size_callback = [this](size_t message_size) {
        statistics_.received_bytes += message_size;
    };
    auto sentry_malformed_message_callback = [this]() {
        statistics_.malformed_msgs++;
    };

    try {
        boost::signals2::scoped_connection c1(sentry_.announcements_subscription.connect(announcement_receiving_callback));
        boost::signals2::scoped_connection c2(sentry_.requests_subscription.connect(response_receiving_callback));
        boost::signals2::scoped_connection c3(sentry_.received_message_size_subscription.connect(sentry_received_message_size_callback));
        boost::signals2::scoped_connection c4(sentry_.malformed_message_subscription.connect(sentry_malformed_message_callback));

        time_point_t last_update = system_clock::now();

        while (!is_stopping()) {
            // pop a message from the queue
            std::shared_ptr<Message> message;
            bool present = messages_.timed_wait_and_pop(message, 100ms);

            // process an external message (replay to remote peers) or an internal message
            if (present) {
                message->execute(db_access_, header_chain_, body_sequence_, sentry_);
                statistics_.processed_msgs++;
            }

            // if we have too many messages in the queue, let's process them
            if (messages_.size() >= 2 * SentryClient::kPerPeerMaxOutstandingRequests * sentry_.active_peers()) {
                continue;
            }

            auto now = system_clock::now();

            // request headers & bodies from remote peers
            size_t outstanding_requests = header_chain_.outstanding_requests(now) +
                                          body_sequence_.outstanding_requests(now);
            size_t peers_capacity = SentryClient::kPerPeerMaxOutstandingRequests * sentry_.active_peers();
            size_t room_for_new_requests = peers_capacity > outstanding_requests ? peers_capacity - outstanding_requests : 0;

            auto body_requests = room_for_new_requests == 1
                                     ? Singleton<RandomNumber>::instance().generate_one() % 2  // 50% chance to request a body
                                     : room_for_new_requests / 2;                              // a slight bias towards headers

            room_for_new_requests -= request_bodies(now, body_requests);           // do the computed nr. of body requests
            room_for_new_requests -= request_headers(now, room_for_new_requests);  // do the remaining nr. of header requests

            request_bodies(now, room_for_new_requests);  // if headers do not used all the room we use it for body requests

            // todo: check if it is better to apply a policy based on the current sync status
            // for example: if (header_chain_.current_height() - body_sequence_.current_height() > stride) { ... }

            // collect downloaded headers & bodies
            collect_headers();
            collect_bodies();

            in_sync_ = header_chain_.in_sync() && body_sequence_.has_completed();
            current_height_ = body_sequence_.highest_block_in_output();

            // log status
            if (silkworm::log::test_verbosity(silkworm::log::Level::kDebug) && now - last_update > 30s) {
                log_status();
                last_update = now;
            }
        }

        log::Debug("BlockExchange") << "execution_loop is stopping...";
    } catch (std::exception& e) {
        log::Error("BlockExchange") << "execution loop aborted due to exception: " << e.what();
    }

    stop();
}

size_t BlockExchange::request_headers(time_point_t tp, size_t max_requests) {
    if (max_requests == 0) return 0;
    if (!downloading_active_) return 0;
    if (header_chain_.in_sync()) return 0;

    size_t sent_requests = 0;
    do {
        auto request_message = header_chain_.request_headers(tp);
        statistics_.tried_msgs += 1;

        if (!request_message) break;

        request_message->execute(db_access_, header_chain_, body_sequence_, sentry_);

        statistics_.sent_msgs += request_message->sent_requests();
        statistics_.nack_msgs += request_message->nack_requests();

        if (request_message->nack_requests() > 0) break;

        sent_requests++;
    } while (sent_requests < max_requests);

    return sent_requests;
}

size_t BlockExchange::request_bodies(time_point_t tp, size_t max_requests) {
    if (max_requests == 0) return 0;
    if (!downloading_active_) return 0;
    if (body_sequence_.has_completed()) return 0;

    size_t sent_requests = 0;
    do {
        auto request_message = body_sequence_.request_bodies(tp);
        statistics_.tried_msgs += 1;

        if (!request_message) break;

        request_message->execute(db_access_, header_chain_, body_sequence_, sentry_);

        statistics_.sent_msgs += request_message->sent_requests();
        statistics_.nack_msgs += request_message->nack_requests();

        if (request_message->nack_requests() > 0) break;

        sent_requests++;
    } while (sent_requests < max_requests);

    return sent_requests;
}

void BlockExchange::collect_headers() {
    if (!downloading_active_) return;

    auto ready_headers = header_chain_.withdraw_stable_headers();
    if (ready_headers.empty()) return;

    body_sequence_.download_bodies(ready_headers);
}

void BlockExchange::collect_bodies() {
    if (!downloading_active_) return;

    auto ready_blocks = body_sequence_.withdraw_ready_bodies();
    if (ready_blocks.empty()) return;

    results_.push(std::move(ready_blocks));
}

void BlockExchange::log_status() {
    static constexpr seconds_t interval_for_stats_{60};
    static Network_Statistics prev_statistic{};
    auto now = std::chrono::system_clock::now();

    log::Debug() << "BlockExchange         peers: " << sentry_.active_peers();
    log::Debug() << "BlockExchange      messages: " << std::setfill('_') << std::right
                 << "in-queue:" << std::setw(5) << messages_.size()
                 //<< ", peers:"     << std::setw(2) << sentry_.active_peers()
                 << Interval_Network_Statistics{prev_statistic, statistics_, interval_for_stats_};

    auto [min_anchor_height, max_anchor_height] = header_chain_.anchor_height_range();
    log::Debug() << "BlockExchange header queues: " << std::setfill('_') << std::right
                 << "links= " << std::setw(7) << header_chain_.pending_links()
                 << ", anchors= " << std::setw(3) << header_chain_.anchors()
                 << ", db-height= " << std::setw(10) << header_chain_.highest_block_in_db()
                 << ", mem-height= " << std::setw(10) << min_anchor_height
                 << "~" << std::setw(10) << max_anchor_height
                 << " (#" << std::setw(7) << std::showpos
                 << max_anchor_height - min_anchor_height << ")"
                 << ", net-height= " << std::setw(10) << header_chain_.top_seen_block_height();

    log::Debug() << "BlockExchange   body queues: " << std::setfill('_') << std::right
                 << "outst= " << std::setw(7)
                 << body_sequence_.outstanding_requests(now) * BodySequence::kMaxBlocksPerMessage
                 << ", ready= " << std::setw(5) << body_sequence_.ready_bodies()
                 << ", db-height= " << std::setw(10) << body_sequence_.highest_block_in_output()
                 << ", mem-height= " << std::setw(10) << body_sequence_.lowest_block_in_memory()
                 << "~" << std::setw(10) << body_sequence_.highest_block_in_memory()
                 << " (#" << std::setw(7) << std::showpos
                 << body_sequence_.highest_block_in_memory() - body_sequence_.lowest_block_in_memory() << ")"
                 << ", net-height= " << std::setw(10) << body_sequence_.target_height();

    log::Debug() << "BlockExchange  header stats: " << header_chain_.statistics();

    log::Debug() << "BlockExchange    body stats: " << body_sequence_.statistics();

    prev_statistic.inaccurate_copy(statistics_);  // save values
}

void BlockExchange::initial_state(std::vector<BlockHeader> last_headers) {
    auto message = std::make_shared<InternalMessage<void>>(
        [h = std::move(last_headers)](HeaderChain& hc, BodySequence&) {
            hc.initial_state(h);
        });

    accept(message);
}

void BlockExchange::download_blocks(BlockNum current_height, Target_Tracking) {
    // todo: handle the Target_Tracking mode

    auto message = std::make_shared<InternalMessage<void>>(
        [=, this](HeaderChain& hc, BodySequence& bc) {
            hc.current_state(current_height);
            bc.current_state(current_height);
            downloading_active_ = true;  // must be done after sync current_state
        });

    accept(message);
}

void BlockExchange::stop_downloading() {
    downloading_active_ = false;
}

void BlockExchange::new_target_block(std::shared_ptr<Block> block) {
    auto message = std::make_shared<InternalMessage<void>>(
        [block = std::move(block)](HeaderChain& hc, BodySequence& bc) {
            hc.add_header(block->header, std::chrono::system_clock::now());
            bc.accept_new_block(*block, no_peer);
        });

    accept(message);
}

}  // namespace silkworm
