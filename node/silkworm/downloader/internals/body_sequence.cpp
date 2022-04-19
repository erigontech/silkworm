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
#include <silkworm/consensus/base/engine.hpp>

#include "body_sequence.hpp"
#include "body_elements.hpp"

namespace silkworm {

BodySequence::BodySequence(const Db::ReadOnlyAccess& dba, const ChainIdentity& ci)
    : db_access_(dba), chain_identity_(ci) {
    recover_initial_state();
}

BodySequence::~BodySequence() {

}

BlockNum BodySequence::highest_block_in_db() { return highest_block_in_db_; }

void BodySequence::sync_current_state(BlockNum highest_in_db) {
    highest_block_in_db_ = highest_in_db;
}

auto BodySequence::accept_bodies(const std::vector<BlockBody>& bodies, [[maybe_unused]] uint64_t req_id, const PeerId&)
    -> std::tuple<Penalty, RequestMoreBodies> {

    Penalty penalty = NoPenalty;
    bool request_more_bodies = false;

    for (auto& body: bodies) {
        Hash oh = consensus::EngineBase::compute_ommers_hash(body);
        Hash tr = consensus::EngineBase::compute_transaction_root(body);

        auto r = std::find_if(body_requests_.begin(), body_requests_.end(), [&oh, &tr](const PendingBodyRequest& request) {
            return (request.header.ommers_hash == oh && request.header.transactions_root == tr);
        }); // todo: can we use request_id to do the match here to speed the check?

        if (r == body_requests_.end()) {
            penalty = BadBlockPenalty;
            continue;
        }

        PendingBodyRequest& request = r->second;
        request.body = std::move(body);
        request.ready = true;
    }

    return {penalty, request_more_bodies};
}

auto BodySequence::request_more_bodies(time_point_t tp, seconds_t timeout)
    -> std::tuple<std::optional<GetBlockBodiesPacket66>, std::vector<PeerPenalization>> {
    GetBlockBodiesPacket66 packet;

    auto penalizations = renew_stale_requests(packet, tp, timeout);

    if (packet.request.size() < max_blocks_per_message) make_new_requests(packet, tp, timeout);

    return {packet, penalizations};
}

//! Re-evaluate past (stale) requests
auto BodySequence::renew_stale_requests(GetBlockBodiesPacket66& packet, time_point_t tp, seconds_t timeout)
    -> std::vector<PeerPenalization> {

    std::vector<PeerPenalization> penalizations;

    for (auto& br: body_requests_) {
        PendingBodyRequest& past_request = br.second;

        if (tp - past_request.request_time < timeout)
            continue;

        // retry body request, todo: Erigon delete the request here, but will it retry?
        packet.request.push_back(past_request.block_hash);
        past_request.request_time = tp;

        // todo: Erigon increment a penalization counter for the peer but it doesn't use it
        //penalizations.emplace_back({Penalty::BadBlockPenalty, }); // todo: find/create a more precise penalization

        if (packet.request.size() >= max_blocks_per_message) break;
    }

    return penalizations;
}

//! Make requests of new bodies to get progress
void BodySequence::make_new_requests(GetBlockBodiesPacket66& packet, time_point_t tp, seconds_t) {
    auto tx = db_access_.start_ro_tx();

    BlockNum last_requested_block = highest_block_in_db_;
    if (!body_requests_.empty())
        last_requested_block = body_requests_.rbegin()->second.block_height; // the last requested

    while (packet.request.size() <= max_blocks_per_message && last_requested_block < top_seen_height_) {
        BlockNum bn = last_requested_block + 1;

        auto new_request = body_requests_[bn]; // insert the new request
        new_request.block_height = bn;

        auto header = tx.read_canonical_header(bn);
        if (!header) {
            body_requests_.erase(bn);
            throw std::logic_error("BodySequence exception, "
                "cause: block " + std::to_string(bn) + " expected in db");
        }

        new_request.block_hash = header->hash();
        new_request.header = std::move(*header);
        new_request.request_time = tp;

        std::optional<BlockBody> announced_body = announced_blocks_.remove(bn);
        if (announced_body && is_valid_body(*header, *announced_body)) {
            add_to_announcements(*header, *announced_body);

            new_request.body = std::move(*announced_body);
            new_request.ready = true;
        }
        else {
            packet.request.push_back(new_request.block_hash);
        }

        ++last_requested_block;
    }

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

        ready_bodies.push_back({std::move(past_request.body), std::move(past_request.header)});
        curr_req = body_requests_.erase(curr_req);  // erase curr_req and update curr_req to point to the next request
    }

    return ready_bodies;
}

void BodySequence::add_to_announcements(BlockHeader header, BlockBody body) {
/*
    todo: check that we do not need this code here

    // calculate total difficulty of the block (it's not imported yet, so block.Td is not valid)
    auto parent_td = tx.read_total_difficulty(block.header.number -1, block.header.parent_hash);
    if (!parent_td) {
        log::Trace() << "[WARN] BodySequence: dangling block " << std::to_string(block.header.number);
        return;
    }
    auto td = parent_td + canonical_difficulty(block.header.number, block.header.timestamp,
                                               parent_td, parent_ts, parent_has_uncle, chain_config_);
    // add to list
    announcements_to_do_.emplace_back({std::move(block), td});
*/

    BigInt td = header.difficulty;
    NewBlockPacket packet{{std::move(body), std::move(header)}, td};

    announcements_to_do_.push_back(std::move(packet));
}

void BodySequence::AnnouncedBlocks::add(Block block) {
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

}