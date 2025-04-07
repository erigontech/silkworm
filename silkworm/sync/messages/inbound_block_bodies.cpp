// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "inbound_block_bodies.hpp"

#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/sync/internals/body_sequence.hpp>
#include <silkworm/sync/sentry_client.hpp>

namespace silkworm {

InboundBlockBodies::InboundBlockBodies(ByteView data, PeerId peer_id)
    : peer_id_(std::move(peer_id)) {
    success_or_throw(rlp::decode(data, packet_));
    SILK_TRACE << "Received message " << *this;
}

void InboundBlockBodies::execute(db::DataStoreRef, HeaderChain&, BodySequence& bs, SentryClient& sentry) {
    SILK_TRACE << "Processing message " << *this;

    Penalty penalty = bs.accept_requested_bodies(packet_, peer_id_);

    if (penalty != Penalty::kNoPenalty) {
        SILK_TRACE << "Replying to " << identify(*this) << " with penalize_peer";
        SILK_TRACE << "Penalizing " << PeerPenalization{penalty, peer_id_};
        try {
            sentry.penalize_peer(peer_id_, penalty);
        } catch (const boost::system::system_error& se) {
            SILK_TRACE << "InboundBlockBodies failed penalize_peer error: " << se.what();
        }
    }
}

uint64_t InboundBlockBodies::req_id() const { return packet_.request_id; }

std::string InboundBlockBodies::content() const {
    std::stringstream content;
    log::prepare_for_logging(content);
    content << packet_;
    return content.str();
}

}  // namespace silkworm