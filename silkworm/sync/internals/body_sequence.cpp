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

#include "body_sequence.hpp"

#include <silkworm/core/common/random_number.hpp>
#include <silkworm/core/common/singleton.hpp>
#include <silkworm/core/protocol/validation.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/sync/sentry_client.hpp>

namespace silkworm {

void BodySequence::current_state(BlockNum highest_in_db) {
    highest_body_in_output_ = highest_in_db;
    target_height_ = highest_in_db;
    statistics_ = {};  // reset statistics
}

BlockNum BodySequence::highest_block_in_output() const { return highest_body_in_output_; }
BlockNum BodySequence::target_height() const { return target_height_; }
BlockNum BodySequence::highest_block_in_memory() const { return body_requests_.highest_block(); }
BlockNum BodySequence::lowest_block_in_memory() const { return body_requests_.lowest_block(); }
size_t BodySequence::ready_bodies() const { return ready_bodies_; }
size_t BodySequence::requests() const { return body_requests_.size(); }
bool BodySequence::has_completed() const {
    return requests() == 0 &&                            // no more requests
           highest_block_in_output() == target_height_;  // all bodies withdrawn
}

size_t BodySequence::outstanding_requests(time_point_t tp) const {
    size_t requested_bodies{0};

    for (auto& br : body_requests_) {
        const BodyRequest& past_request = br.second;
        if (past_request.request_id == 0) break;  // not yet requested, so the following
        if (!past_request.ready &&
            (tp - past_request.request_time < SentryClient::kRequestDeadline))
            requested_bodies++;
    }

    // return requested_bodies / kMaxBlocksPerMessage rounded up
    return (requested_bodies + kMaxBlocksPerMessage - 1) / kMaxBlocksPerMessage;
}

Penalty BodySequence::accept_requested_bodies(BlockBodiesPacket66& packet, const PeerId& peer) {
    Penalty penalty = NoPenalty;
    BlockNum start_block = std::numeric_limits<BlockNum>::max();
    size_t count = 0;

    statistics_.received_items += packet.request.size();

    // Find matching requests and completing BodyRequest
    auto matching_requests = body_requests_.find_by_request_id(packet.requestId);

    for (auto& body : packet.request) {
        Hash oh = protocol::compute_ommers_hash(body);
        Hash tr = protocol::compute_transaction_root(body);

        auto exact_request = body_requests_.end();  // = no request

        auto r = std::find_if(matching_requests.begin(), matching_requests.end(), [&oh, &tr](const auto& elem) {
            const BodyRequest& request = elem->second;
            return (request.header.ommers_hash == oh && request.header.transactions_root == tr);
        });

        if (r != matching_requests.end()) {
            // found
            exact_request = *r;

            matching_requests.erase(r);
        } else {
            // not found, can be a response to "past" request upon same bodies?
            exact_request = body_requests_.find_by_hash(oh, tr);

            if (exact_request == body_requests_.end()) {
                // penalty = BadBlockPenalty; // Erigon doesn't penalize the peer maybe because can be a late response but
                //  todo: here we are sure it is not a late response, should we penalize the peer?
                SILK_TRACE << "BodySequence: body rejected, no matching requests";
                statistics_.reject_causes.not_requested += 1;
                continue;
            }
        }

        BodyRequest& request = exact_request->second;
        if (!body.withdrawals) {
            SILK_WARN << "BodySequence: body " << request.block_height << " w/o withdrawals received from peer " << to_hex(human_readable_id(peer));
        }
        if (!request.ready) {
            request.body = std::move(body);
            request.ready = true;
            ready_bodies_ += 1;
            statistics_.accepted_items += 1;

            start_block = std::min(start_block, request.block_height);
            count += 1;
            // SILK_TRACE << "BodySequence: body accepted, block_num=" << request.block_height;
        } else {
            statistics_.reject_causes.duplicated += 1;
        }
    }

    SILK_TRACE << "BodySequence: " << count << " body accepted starting at block " << start_block << " out of "
               << packet.request.size() << " received";

    // Process remaining elements in matching_requests invalidating corresponding BodyRequest
    for (auto& elem : matching_requests) {
        BodyRequest& request = elem->second;
        request.request_id = 0;
        request.request_time = time_point_t();
    }

    return penalty;
}

Penalty BodySequence::accept_new_block(const Block& block, const PeerId&) {
    if (block.header.number <= highest_body_in_output_) return Penalty::NoPenalty;  // already in db, ignore

    announced_blocks_.add(block);  // save for later usage

    return Penalty::NoPenalty;
}

std::shared_ptr<OutboundMessage> BodySequence::request_bodies(time_point_t tp) {
    if (tp - last_nack_ < SentryClient::kNoPeerDelay)
        return nullptr;

    auto prev_condition = retrieval_condition_;
    seconds_t timeout = SentryClient::kRequestDeadline;
    BlockNum min_block{0};

    auto body_request = std::make_shared<OutboundGetBlockBodies>();
    auto& packet = body_request->packet();
    packet.requestId = Singleton<RandomNumber>::instance().generate_one();

    auto penalizations = renew_stale_requests(packet, min_block, tp, timeout);

    if (packet.request.size() < kMaxBlocksPerMessage &&  // not full yet
        requests() < kMaxInMemoryRequests) {             // not too many requests in memory
        make_new_requests(packet, min_block, tp, timeout);
    }

    statistics_.requested_items += packet.request.size();

    if (packet.request.empty()) {
        retrieval_condition_ = "no more bodies to request";
        if (retrieval_condition_ != prev_condition) {
            SILK_TRACE << "BodySequence, no more bodies to request";
        }
    } else {
        retrieval_condition_ = "requesting bodies";
    }

    body_request->penalties() = std::move(penalizations);
    body_request->min_block() = min_block;

    return body_request;
}

//! Re-evaluate past (stale) requests
std::vector<PeerPenalization> BodySequence::renew_stale_requests(
    GetBlockBodiesPacket66& packet,
    BlockNum& min_block,
    time_point_t tp,
    seconds_t timeout) {
    std::vector<PeerPenalization> penalizations;
    BlockNum start_block = std::numeric_limits<BlockNum>::max();
    size_t count = 0;

    for (auto& br : body_requests_) {
        BodyRequest& past_request = br.second;

        if (past_request.request_id == 0 || past_request.ready || tp - past_request.request_time < timeout)
            continue;

        if (!fulfill_from_announcements(past_request)) {
            packet.request.push_back(past_request.block_hash);
            past_request.request_time = tp;
            past_request.request_id = packet.requestId;

            min_block = std::max(min_block, past_request.block_height);

            // Erigon increment a penalization counter for the peer, but it doesn't use it
            // penalizations.emplace_back({Penalty::BadBlockPenalty, });

            start_block = std::min(start_block, past_request.block_height);
            count++;
            // SILK_TRACE << "BodySequence: renewed request block num= " << past_request.block_height
            //            << ", hash= " << past_request.block_hash;
        }

        if (packet.request.size() >= kMaxBlocksPerMessage) break;
    }

    if (count) {
        SILK_TRACE << "BodySequence: renewing body requests from block-num " << start_block << " for " << count << " blocks";
    }

    return penalizations;
}

void BodySequence::make_new_requests(GetBlockBodiesPacket66& packet, BlockNum& min_block,
                                     time_point_t tp, seconds_t) {
    BlockNum start_block = std::numeric_limits<BlockNum>::max();
    size_t count = 0;

    for (auto& br : body_requests_) {
        BodyRequest& new_request = br.second;

        if (new_request.request_id != 0 || new_request.ready)  // already requested or ready
            continue;

        if (!fulfill_from_announcements(new_request)) {
            packet.request.push_back(new_request.block_hash);
            new_request.request_time = tp;
            new_request.request_id = packet.requestId;

            min_block = std::max(min_block, new_request.block_height);  // the min block the peer must have (so it is our max)

            start_block = std::min(start_block, new_request.block_height);
            count++;
            // SILK_TRACE << "BodySequence: requested body block-num= " << new_request.block_height
            //            << ", hash= " << new_request.block_hash;
        }

        new_request.request_id = packet.requestId;

        if (packet.request.size() >= kMaxBlocksPerMessage) break;
    }

    if (count) {
        SILK_TRACE << "BodySequence: requesting new bodies from block-num " << start_block << " for " << count << " blocks";
    }
}

//! Save headers of witch it has to download bodies
void BodySequence::download_bodies(const Headers& headers) {
    for (const auto& header : headers) {
        BlockNum bn = header->number;

        BodyRequest new_request;
        new_request.block_height = header->number;
        new_request.request_id = 0;  // no request yet
        new_request.block_hash = header->hash();
        // new_request.request_time

        fulfill_from_announcements(new_request);

        new_request.header = *header;

        body_requests_.emplace(bn, std::move(new_request));

        target_height_ = std::max(target_height_, bn);
    }
}

// fill BodyRequest from announced_blocks_
bool BodySequence::fulfill_from_announcements(BodyRequest& request) {
    if (request.ready) return false;

    std::optional<BlockBody> announced_body = announced_blocks_.remove(request.block_height);
    if (announced_body && is_valid_body(request.header, *announced_body)) {
        request.body = std::move(*announced_body);
        request.ready = true;
        request.to_announce = true;
        ready_bodies_ += 1;
        return true;
    }

    return false;
}

void BodySequence::request_nack(const GetBlockBodiesPacket66& packet) {
    seconds_t timeout = SentryClient::kRequestDeadline;
    for (auto& br : body_requests_) {
        BodyRequest& past_request = br.second;
        if (past_request.request_id == packet.requestId)
            past_request.request_time -= timeout;
    }
    last_nack_ = std::chrono::system_clock::now();
    statistics_.requested_items -= packet.request.size();
}

bool BodySequence::is_valid_body(const BlockHeader& header, const BlockBody& body) {
    if (header.ommers_hash != protocol::compute_ommers_hash(body)) {
        return false;
    }
    if (header.transactions_root != protocol::compute_transaction_root(body)) {
        return false;
    }
    return true;
}

Blocks BodySequence::withdraw_ready_bodies() {
    Blocks ready_bodies;

    auto curr_req = body_requests_.begin();
    while (curr_req != body_requests_.end()) {
        BodyRequest& past_request = curr_req->second;
        if (!past_request.ready)
            break;  // it needs to return the first range of consecutive blocks, so it stops at the first non ready

        highest_body_in_output_ = std::max(highest_body_in_output_, past_request.block_height);

        std::shared_ptr<BlockEx> b{new BlockEx{{std::move(past_request.body), std::move(past_request.header)}}};
        b->to_announce = past_request.to_announce;

        ready_bodies.push_back(b);

        curr_req = body_requests_.erase(curr_req);  // erase curr_req and update curr_req to point to the next request
    }

    ready_bodies_ -= ready_bodies.size();
    return ready_bodies;
}

void BodySequence::AnnouncedBlocks::add(Block block) {
    if (blocks_.size() >= kMaxAnnouncedBlocks) {
        return;
    }

    blocks_.emplace(block.header.number, std::move(block));
}

std::optional<BlockBody> BodySequence::AnnouncedBlocks::remove(BlockNum bn) {
    auto b = blocks_.find(bn);
    if (b == blocks_.end())
        return std::nullopt;

    auto block = std::move(b->second);
    blocks_.erase(b);
    return block;
}

size_t BodySequence::AnnouncedBlocks::size() {
    return blocks_.size();
}

std::list<BodySequence::IncreasingHeightOrderedRequestContainer::Iter> BodySequence::IncreasingHeightOrderedRequestContainer::find_by_request_id(uint64_t request_id) {
    std::list<Impl::iterator> matching_requests;
    for (auto elem = begin(); elem != end(); elem++) {
        const BodyRequest& request = elem->second;
        if (request.request_id == request_id) matching_requests.push_back(elem);
    }
    return matching_requests;
}

BodySequence::IncreasingHeightOrderedRequestContainer::Iter BodySequence::IncreasingHeightOrderedRequestContainer::find_by_hash(Hash oh, Hash tr) {
    auto r = std::find_if(begin(), end(), [&oh, &tr](const auto& elem) {
        const BodyRequest& request = elem.second;
        return (request.header.ommers_hash == oh && request.header.transactions_root == tr);
    });

    return r;
}

BlockNum BodySequence::IncreasingHeightOrderedRequestContainer::lowest_block() const {
    if (empty()) return 0;
    return begin()->first;
}

BlockNum BodySequence::IncreasingHeightOrderedRequestContainer::highest_block() const {
    if (empty()) return 0;
    return rbegin()->first;
}

const Download_Statistics& BodySequence::statistics() const {
    return statistics_;
}

}  // namespace silkworm
