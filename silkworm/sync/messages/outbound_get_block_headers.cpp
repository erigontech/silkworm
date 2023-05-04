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

#include "outbound_get_block_headers.hpp"

#include <sstream>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/sync/internals/body_sequence.hpp>
#include <silkworm/sync/internals/header_chain.hpp>
#include <silkworm/sync/sentry_client.hpp>

namespace silkworm {

GetBlockHeadersPacket66& OutboundGetBlockHeaders::packet() { return packet_; }
std::vector<PeerPenalization>& OutboundGetBlockHeaders::penalties() { return penalizations_; }
bool OutboundGetBlockHeaders::packet_present() const { return (packet_.request.amount != 0); }

void OutboundGetBlockHeaders::execute(db::ROAccess, HeaderChain& hc, BodySequence&, SentryClient& sentry) {
    if (packet_present()) {
        auto send_outcome = send_packet(sentry);

        SILK_TRACE << "Headers request sent (OutboundGetBlockHeaders/" << packet_ << "), received by "
                   << send_outcome.size() << "/" << sentry.active_peers() << " peer(s)";

        if (send_outcome.empty()) {
            hc.request_nack(packet_);
            nack_reqs_++;
        } else {
            sent_reqs_++;
        }
    }

    for (auto& penalization : penalizations_) {
        SILK_TRACE << "Penalizing " << penalization;
        sentry.penalize_peer(penalization.peerId, penalization.penalty);
    }
}

Bytes OutboundGetBlockHeaders::message_data() const {
    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, packet_);
    return rlp_encoding;
}

std::vector<PeerId> OutboundGetBlockHeaders::send_packet(SentryClient& sentry) {
    if (std::holds_alternative<Hash>(packet_.request.origin))
        throw std::logic_error("OutboundGetBlockHeaders expects block number not hash");

    if (std::get<BlockNum>(packet_.request.origin) == 0 || packet_.request.amount == 0)
        throw std::logic_error("OutboundGetBlockHeaders expects block number > 0 and amount > 0");

    BlockNum min_block = std::get<BlockNum>(packet_.request.origin);  // choose target peer
    if (!packet_.request.reverse) min_block += packet_.request.amount * packet_.request.skip;

    // SILK_TRACE << "Sending message OutboundGetBlockHeaders with send_message_by_min_block, content:" << packet_;

    auto peers = sentry.send_message_by_min_block(*this, min_block, 0);

    // SILK_TRACE << "Received sentry result of OutboundGetBlockHeaders reqId=" << packet_.requestId << ": "
    //            << std::to_string(peers.size()) + " peer(s)";

    return peers;
}

std::string OutboundGetBlockHeaders::content() const {
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