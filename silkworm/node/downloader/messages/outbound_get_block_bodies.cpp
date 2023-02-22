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

#include "outbound_get_block_bodies.hpp"

#include <sstream>

#include <silkworm/node/common/log.hpp>
#include <silkworm/node/downloader/internals/body_sequence.hpp>
#include <silkworm/node/downloader/internals/header_chain.hpp>
#include <silkworm/node/downloader/rpc/penalize_peer.hpp>
#include <silkworm/node/downloader/rpc/send_message_by_min_block.hpp>

namespace silkworm {

OutboundGetBlockBodies::OutboundGetBlockBodies() {}

GetBlockBodiesPacket66& OutboundGetBlockBodies::packet() { return packet_; }
std::vector<PeerPenalization>& OutboundGetBlockBodies::penalties() { return penalizations_; }
BlockNum& OutboundGetBlockBodies::min_block() { return min_block_; }
bool OutboundGetBlockBodies::packet_present() const { return !packet_.request.empty(); }

void OutboundGetBlockBodies::execute(db::ROAccess, HeaderChain&, BodySequence& bs, SentryClient& sentry) {
    using namespace std::literals::chrono_literals;

    seconds_t timeout = 1s;

    if (packet_present()) {
        auto send_outcome = send_packet(sentry, timeout);

        SILK_TRACE << "Bodies request sent (OutboundGetBlockBodies/" << packet_ << "), min_block " << min_block_
                   << ", received by " << send_outcome.peers_size() << "/" << sentry.active_peers() << " peer(s)";

        if (send_outcome.peers_size() == 0) {
            bs.request_nack(packet_);
            nack_reqs_++;
        } else {
            sent_reqs_++;
        }
    }

    for (auto& penalization : penalizations_) {
        SILK_TRACE << "Penalizing " << penalization;
        send_penalization(sentry, penalization, 1s);
    }

}

sentry::SentPeers OutboundGetBlockBodies::send_packet(SentryClient& sentry, seconds_t timeout) {
    auto request = std::make_unique<sentry::OutboundMessageData>();  // create header request

    request->set_id(sentry::MessageId::GET_BLOCK_BODIES_66);

    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, packet_);
    request->set_data(rlp_encoding.data(), rlp_encoding.length());  // copy

    // SILK_TRACE << "Sending message OutboundGetBlockBodies with send_message_by_min_block, content:" << packet_;

    rpc::SendMessageByMinBlock rpc{min_block_, std::move(request)};

    rpc.timeout(timeout);
    rpc.do_not_throw_on_failure();

    sentry.exec_remotely(rpc);

    if (!rpc.status().ok()) {
        SILK_TRACE << "Failure of rpc OutboundGetBlockBodies " << packet_ << ": " << rpc.status().error_message();
        return {};
    }

    sentry::SentPeers peers = rpc.reply();
    // SILK_TRACE << "Received rpc result of OutboundGetBlockBodies reqId=" << packet_.requestId << ": "
    //            << std::to_string(peers.peers_size()) + " peer(s)";

    return peers;
}

void OutboundGetBlockBodies::send_penalization(SentryClient& sentry, const PeerPenalization& penalization,
                                               seconds_t timeout) {
    rpc::PenalizePeer rpc{penalization.peerId, penalization.penalty};

    rpc.timeout(timeout);

    sentry.exec_remotely(rpc);
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