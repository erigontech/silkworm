// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "inbound_new_block_hashes.hpp"

#include <algorithm>

#include <silkworm/core/common/random_number.hpp>
#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/sync/internals/header_chain.hpp>
#include <silkworm/sync/internals/random_number.hpp>
#include <silkworm/sync/sentry_client.hpp>

#include "outbound_get_block_headers.hpp"

namespace silkworm {

InboundNewBlockHashes::InboundNewBlockHashes(ByteView data, PeerId peer_id)
    : peer_id_(std::move(peer_id)),
      req_id_(chainsync::random_number.generate_one())  // for trace purposes
{
    success_or_throw(rlp::decode(data, packet_));
    SILK_TRACE << "Received message " << *this;
}

void InboundNewBlockHashes::execute(db::DataStoreRef, HeaderChain& hc, BodySequence&, SentryClient& sentry) {
    using namespace std;

    SILK_TRACE << "Processing message " << *this;

    BlockNum max = hc.top_seen_block_num();

    for (auto& new_block_hash : packet_) {
        Hash hash = new_block_hash.hash;

        // calculate top seen block number
        max = std::max(max, new_block_hash.block_num);

        // save announcement
        auto packet = hc.save_external_announce(hash);
        if (!packet) continue;

        // request header
        SILK_TRACE << "Replying to " << identify(*this) << " requesting header with send_message_by_id, content: " << *packet;

        try {
            OutboundGetBlockHeaders request_message{packet.value()};
            [[maybe_unused]] auto peers = sentry.send_message_by_id(request_message, peer_id_);

            SILK_TRACE << "Received sentry result of " << identify(*this) << ": "
                       << std::to_string(peers.size()) + " peer(s)";
        } catch (const boost::system::system_error& se) {
            SILK_TRACE << "Received error from sentry send_message_by_id for " << identify(*this) << " error: " << se.what();
        }
    }

    hc.top_seen_block_num(max);
}

uint64_t InboundNewBlockHashes::req_id() const { return req_id_; }

std::string InboundNewBlockHashes::content() const {
    std::stringstream content;
    log::prepare_for_logging(content);
    content << packet_;
    return content.str();
}

}  // namespace silkworm