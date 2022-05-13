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

#include <silkworm/chain/difficulty.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/consensus/base/engine.hpp>

#include "body_sequence.hpp"
#include "random_number.hpp"

namespace silkworm {

BodySequence::BodySequence(const Db::ReadOnlyAccess& dba, const ChainIdentity& ci)
    : db_access_(dba), chain_identity_(ci) {
    recover_initial_state();
}

BodySequence::~BodySequence() {

}

void BodySequence::recover_initial_state() {
    // does nothing
}

BlockNum BodySequence::highest_block_in_db() const { return highest_body_in_db_; }

void BodySequence::sync_current_state(BlockNum highest_body_in_db, BlockNum highest_header_in_db) {
    highest_body_in_db_ = highest_body_in_db;
    headers_stage_height_ = highest_header_in_db;

    statistics_ = {}; // reset statistics
}

size_t BodySequence::outstanding_requests(time_point_t tp, seconds_t timeout) const {
    size_t requested_bodies{0};

    for (auto& br: body_requests_) {
        const PendingBodyRequest& past_request = br.second;
        if (!past_request.ready &&
            (tp - past_request.request_time < timeout))
            requested_bodies++;
    }

    return requested_bodies / kMaxBlocksPerMessage;
}

std::list<NewBlockPacket>& BodySequence::announces_to_do() {
    return announcements_to_do_;
}

Penalty BodySequence::accept_requested_bodies(const BlockBodiesPacket66& packet, const PeerId&) {
    Penalty penalty = NoPenalty;

    statistics_.received_bodies += packet.request.size();

    // Find matching requests and completing PendingBodyRequest
    auto matching_requests = body_requests_.find_by_request_id(packet.requestId);

    for (auto& body: packet.request) {
        Hash oh = consensus::EngineBase::compute_ommers_hash(body);
        Hash tr = consensus::EngineBase::compute_transaction_root(body);

        auto exact_request = body_requests_.end(); // = no request

        auto r = std::find_if(matching_requests.begin(), matching_requests.end(), [&oh, &tr](const auto& elem) {
            const PendingBodyRequest& request = elem->second;
            return (request.header.ommers_hash == oh && request.header.transactions_root == tr);
        });

        if (r != matching_requests.end()) {
            // found
            exact_request = *r;

            matching_requests.erase(r);
        }
        else {
            // not found, can be a response to "past" request upon same bodies?
            exact_request = body_requests_.find_by_hash(oh, tr);

            if (exact_request == body_requests_.end()) {
                penalty = BadBlockPenalty;
                SILK_TRACE << "BodySequence: body rejected, no matching requests";
                continue;
            }
        }

        PendingBodyRequest& request = exact_request->second;
        request.body = std::move(body);
        request.ready = true;

        SILK_TRACE << "BodySequence: body accepted, block_num=" << request.block_height;
        statistics_.accepted_bodies += 1;
    }

    // Process remaining elements in matching_requests invalidating corresponding PendingBodyRequest
    for(auto& elem: matching_requests) {
        PendingBodyRequest& request = elem->second;
        request.request_id = 0;
        request.request_time = time_point_t();
    }

    return penalty;
}

Penalty BodySequence::accept_new_block(const Block& block, const PeerId&) {

    // save for later usage
    announced_blocks_.add(block);

    return Penalty::NoPenalty;
}

auto BodySequence::request_more_bodies(time_point_t tp, seconds_t timeout)
    -> std::tuple<GetBlockBodiesPacket66, std::vector<PeerPenalization>, MinBlock> {
    GetBlockBodiesPacket66 packet;
    packet.requestId = RANDOM_NUMBER.generate_one();

    BlockNum min_block{0};

    if (tp - last_nack < timeout)
        return {};

    if (outstanding_requests(tp, timeout) > kMaxOutstandingRequests)
        return {};

    auto penalizations = renew_stale_requests(packet, min_block, tp, timeout);

    if (packet.request.size() < kMaxBlocksPerMessage) make_new_requests(packet, min_block, tp, timeout);

    statistics_.requested_bodies += packet.request.size();

    return {std::move(packet), std::move(penalizations), min_block};
}

//! Re-evaluate past (stale) requests
auto BodySequence::renew_stale_requests(GetBlockBodiesPacket66& packet, BlockNum& min_block, time_point_t tp, seconds_t timeout)
    -> std::vector<PeerPenalization> {

    std::vector<PeerPenalization> penalizations;

    for (auto& br: body_requests_) {
        PendingBodyRequest& past_request = br.second;

        if (tp - past_request.request_time < timeout)
            continue;

        // retry body request, todo: Erigon delete the request here, but will it retry?
        packet.request.push_back(past_request.block_hash);
        past_request.request_time = tp;
        past_request.request_id = packet.requestId;
        // todo: Erigon increment a penalization counter for the peer but it doesn't use it
        //penalizations.emplace_back({Penalty::BadBlockPenalty, }); // todo: find/create a more precise penalization

        SILK_TRACE << "BodySequence: renewed request block num= " << past_request.block_height
                   << ", hash= " << past_request.block_hash;

        min_block = std::max(min_block, past_request.block_height);

        if (packet.request.size() >= kMaxBlocksPerMessage) break;
    }

    return penalizations;
}

//! Make requests of new bodies to get progress
void BodySequence::make_new_requests(GetBlockBodiesPacket66& packet, BlockNum& min_block, time_point_t tp, seconds_t) {
    auto tx = db_access_.start_ro_tx();

    BlockNum last_requested_block = highest_body_in_db_;
    if (!body_requests_.empty())
        last_requested_block = body_requests_.rbegin()->second.block_height; // the last requested

    while (packet.request.size() < kMaxBlocksPerMessage && last_requested_block <= headers_stage_height_) {
        BlockNum bn = last_requested_block + 1;

        auto header = tx.read_canonical_header(bn);
        if (!header) {
            body_requests_.erase(bn);
            throw std::logic_error("BodySequence exception, "
                "cause: header of block " + std::to_string(bn) + " expected in db");
        }

        PendingBodyRequest new_request;
        new_request.block_height = bn;
        new_request.request_id = packet.requestId;
        new_request.block_hash = header->hash();
        new_request.request_time = tp;

        std::optional<BlockBody> announced_body = announced_blocks_.remove(bn);
        if (announced_body && is_valid_body(*header, *announced_body)) {
            add_to_announcements(*header, *announced_body, tx);

            new_request.body = std::move(*announced_body);
            new_request.ready = true;
        }
        else {
            packet.request.push_back(new_request.block_hash);
            SILK_TRACE << "BodySequence: requested body block-num= " << new_request.block_height
                       << ", hash= " << new_request.block_hash;
            min_block = std::max(min_block, new_request.block_height);
        }

        new_request.header = std::move(*header);

        body_requests_.emplace(bn, std::move(new_request));

        ++last_requested_block;
    }

}

void BodySequence::request_nack(const std::vector<Hash>& hashes, time_point_t tp, seconds_t timeout) {
    for (auto& br: body_requests_) {
        PendingBodyRequest& past_request = br.second;
        if (contains(hashes, past_request.block_hash))
            past_request.request_time -= timeout;
    }
    last_nack = tp;
}

bool BodySequence::is_valid_body(const BlockHeader& header, const BlockBody& body) {
    if (header.ommers_hash != consensus::EngineBase::compute_ommers_hash(body))
        return false;
    if (header.transactions_root != consensus::EngineBase::compute_transaction_root(body))
        return false;
    return true;
}

auto BodySequence::withdraw_ready_bodies() -> std::vector<Block> {
    std::vector<Block> ready_bodies;

    auto curr_req = body_requests_.begin();
    while (curr_req != body_requests_.end()) {
        PendingBodyRequest& past_request = curr_req->second;
        if (!past_request.ready)
            break; // it needs to return the first range of consecutive blocks, so it stops at the first non ready

        highest_body_in_db_ = std::max(highest_body_in_db_, past_request.block_height);
        ready_bodies.push_back({std::move(past_request.body), std::move(past_request.header)});

        curr_req = body_requests_.erase(curr_req);  // erase curr_req and update curr_req to point to the next request
    }

    return ready_bodies;
}

void BodySequence::add_to_announcements(BlockHeader header, BlockBody body, Db::ReadOnlyAccess::Tx& tx) {

    // calculate total difficulty of the block
    auto parent_td = tx.read_total_difficulty(header.number -1, header.parent_hash);
    if (!parent_td) {
        log::Warning() << "BodySequence: dangling block " << std::to_string(header.number);
        return; // non inserted in announcement list
    }

    auto td = *parent_td + header.difficulty;

    //auto td = parent_td + canonical_difficulty(header.number, header.timestamp,
    //                                           parent_td, parent_ts, parent_has_uncle, chain_config_);

    NewBlockPacket packet{{std::move(body), std::move(header)}, td};

    // add to list
    announcements_to_do_.push_back(std::move(packet));
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

    std::optional<BlockBody> body = std::move(b->second);
    blocks_.erase(b);
    return body;
}

auto BodySequence::IncreasingHeightOrderedRequestContainer::find_by_request_id(uint64_t request_id) -> std::list<Iter> {
    std::list<Impl::iterator> matching_requests;
    for (auto elem = begin(); elem != end(); elem++) {
        const PendingBodyRequest& request = elem->second;
        if (request.request_id == request_id) matching_requests.push_back(elem);
    }
    return matching_requests;
}

auto BodySequence::IncreasingHeightOrderedRequestContainer::find_by_hash(Hash oh, Hash tr) -> Iter {
    auto r = std::find_if(begin(), end(), [&oh, &tr](const auto& elem) {
        const PendingBodyRequest& request = elem.second;
        return (request.header.ommers_hash == oh && request.header.transactions_root == tr);
    });

    return r;
}

std::string BodySequence::human_readable_status() const {
    using namespace std::chrono_literals;
    std::ostringstream output;

    output << std::setfill('_')
           << "reqs= " << std::setw(7) << std::right << outstanding_requests(std::chrono::system_clock::now(), 1min)
           << ", db-height= " << std::setw(10) << std::right << highest_body_in_db_
           << ", net-height= " << std::setw(10) << std::right << headers_stage_height_;

    return output.str();
}

std::string BodySequence::human_readable_stats() const {
    return statistics_.human_readable_report();
}

std::string BodySequence::Statistics::human_readable_report() const {
    std::ostringstream os;
    uint64_t rejected_bodies = received_bodies - accepted_bodies;
    uint64_t perc_received = requested_bodies > 0 ? received_bodies * 100 / requested_bodies : 0;
    uint64_t perc_accepted = received_bodies > 0 ? accepted_bodies * 100 / received_bodies : 0;
    uint64_t perc_rejected = received_bodies > 0 ? rejected_bodies * 100 / received_bodies : 0;
    os << "req=" << requested_bodies << " "
       << "rec=" << received_bodies << " (" << perc_received << "%) -> "
       << "acc=" << accepted_bodies << " (" << perc_accepted << "%) "
       << "rej=" << rejected_bodies << " (" << perc_rejected << "%)";
    return os.str();
}

}