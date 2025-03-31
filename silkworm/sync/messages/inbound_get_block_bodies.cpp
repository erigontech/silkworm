// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "inbound_get_block_bodies.hpp"

#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/sync/internals/body_retrieval.hpp>
#include <silkworm/sync/internals/body_sequence.hpp>
#include <silkworm/sync/messages/outbound_block_bodies.hpp>
#include <silkworm/sync/packets/block_bodies_packet.hpp>
#include <silkworm/sync/sentry_client.hpp>

namespace silkworm {

InboundGetBlockBodies::InboundGetBlockBodies(ByteView data, PeerId peer_id)
    : peer_id_(std::move(peer_id)) {
    success_or_throw(rlp::decode(data, packet_));
    SILK_TRACE << "Received message " << *this;
}

void InboundGetBlockBodies::execute(db::DataStoreRef db, HeaderChain&, BodySequence& bs, SentryClient& sentry) {
    using namespace std;

    SILK_TRACE << "Processing message " << *this;

    if (bs.max_block_in_output() == 0)
        return;

    datastore::kvdb::ROTxnManaged tx = db.chaindata.access_ro().start_ro_tx();
    BodyRetrieval body_retrieval{tx};

    BlockBodiesPacket66 reply;
    reply.request_id = packet_.request_id;
    reply.request = body_retrieval.recover(packet_.request);

    if (reply.request.empty()) {
        SILK_TRACE << "[WARNING] Not replying to " << identify(*this) << ", no blocks found";
        return;
    }

    SILK_TRACE << "Replying to " << identify(*this) << " using send_message_by_id with "
               << reply.request.size() << " bodies";

    try {
        OutboundBlockBodies reply_message{std::move(reply)};
        [[maybe_unused]] auto peers = sentry.send_message_by_id(reply_message, peer_id_);

        SILK_TRACE << "Received sentry result of " << identify(*this) << ": " << std::to_string(peers.size()) + " peer(s)";
    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "InboundGetBlockBodies failed send_message_by_id error: " << se.what();
    }
}

uint64_t InboundGetBlockBodies::req_id() const { return packet_.request_id; }

std::string InboundGetBlockBodies::content() const {
    std::stringstream content;
    log::prepare_for_logging(content);
    content << packet_;
    return content.str();
}

}  // namespace silkworm
