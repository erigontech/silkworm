// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "outbound_get_block_bodies.hpp"

#include <sstream>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/sync/internals/body_sequence.hpp>
#include <silkworm/sync/internals/header_chain.hpp>
#include <silkworm/sync/sentry_client.hpp>

namespace silkworm {

GetBlockBodiesPacket66& OutboundGetBlockBodies::packet() { return packet_; }
std::vector<PeerPenalization>& OutboundGetBlockBodies::penalties() { return penalizations_; }
BlockNum& OutboundGetBlockBodies::min_block() { return min_block_; }
bool OutboundGetBlockBodies::packet_present() const { return !packet_.request.empty(); }

void OutboundGetBlockBodies::execute(db::DataStoreRef, HeaderChain&, BodySequence& bs, SentryClient& sentry) {
    if (packet_present()) {
        try {
            auto send_outcome = send_packet(sentry);

            SILK_TRACE << "Bodies request sent (OutboundGetBlockBodies/" << packet_ << "), min_block " << min_block_
                       << ", received by " << send_outcome.size() << "/" << sentry.active_peers() << " peer(s)";

            if (send_outcome.empty()) {
                bs.request_nack(packet_);
                ++nack_reqs_;
            } else {
                ++sent_reqs_;
            }
        } catch (const boost::system::system_error& se) {
            SILK_TRACE << "OutboundGetBlockBodies failed send_packet error: " << se.what();
            bs.request_nack(packet_);
        }
    }

    for (auto& penalization : penalizations_) {
        try {
            SILK_TRACE << "Penalizing " << penalization;
            sentry.penalize_peer(penalization.peer_id, penalization.penalty);
        } catch (const boost::system::system_error& se) {
            SILK_TRACE << "OutboundGetBlockBodies failed penalizing " << penalization << " error: " << se.what();
        }
    }
}

Bytes OutboundGetBlockBodies::message_data() const {
    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, packet_);
    return rlp_encoding;
}

std::vector<PeerId> OutboundGetBlockBodies::send_packet(SentryClient& sentry) {
    // SILK_TRACE << "Sending message OutboundGetBlockBodies with send_message_by_min_block, content:" << packet_;

    auto peers = sentry.send_message_by_min_block(*this, min_block_, 0);

    // SILK_TRACE << "Received sentry result of OutboundGetBlockBodies reqId=" << packet_.request_id << ": "
    //            << std::to_string(peers.size()) + " peer(s)";

    return peers;
}

std::string OutboundGetBlockBodies::content() const {
    std::stringstream content;
    log::prepare_for_logging(content);
    if (packet_present())
        content << packet_;
    if (!penalizations_.empty()) {
        content << " penalizations: ";
        for (auto& penalization : penalizations_) {
            content << " " << penalization << ", ";
        }
    }
    if (!packet_present() && penalizations_.empty())
        content << "-no message-";
    return content.str();
}

}  // namespace silkworm