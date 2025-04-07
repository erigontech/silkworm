// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "inbound_block_headers.hpp"

#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/sync/internals/header_chain.hpp>
#include <silkworm/sync/sentry_client.hpp>

namespace silkworm {

InboundBlockHeaders::InboundBlockHeaders(ByteView data, PeerId peer_id)
    : peer_id_(std::move(peer_id)) {
    success_or_throw(rlp::decode(data, packet_));
    SILK_TRACE << "Received message " << *this;
}

void InboundBlockHeaders::execute(db::DataStoreRef, HeaderChain& hc, BodySequence&, SentryClient& sentry) {
    using namespace std;

    SILK_TRACE << "Processing message " << *this;

    BlockNum max_block_num = 0;
    for (BlockHeader& header : packet_.request) {
        max_block_num = std::max(max_block_num, header.number);
    }

    // Save the headers
    auto [penalty, requestMoreHeaders] = hc.accept_headers(packet_.request, packet_.request_id, peer_id_);

    // Reply
    if (penalty != Penalty::kNoPenalty) {
        SILK_TRACE << "Replying to " << identify(*this) << " with penalize_peer";
        SILK_TRACE << "Penalizing " << PeerPenalization{penalty, peer_id_};
        try {
            sentry.penalize_peer(peer_id_, penalty);
        } catch (const boost::system::system_error& se) {
            SILK_TRACE << "InboundBlockHeaders failed penalize_peer error: " << se.what();
        }
    }

    try {
        SILK_TRACE << "Replying to " << identify(*this) << " with peer_min_block";
        sentry.peer_min_block(peer_id_, max_block_num);
    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "InboundBlockHeaders failed peer_min_block error: " << se.what();
    }
}

uint64_t InboundBlockHeaders::req_id() const { return packet_.request_id; }

std::string InboundBlockHeaders::content() const {
    std::stringstream content;
    log::prepare_for_logging(content);
    content << packet_;
    return content.str();
}

}  // namespace silkworm