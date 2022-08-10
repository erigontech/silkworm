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

#include <silkworm/common/log.hpp>
#include <silkworm/downloader/rpc/penalize_peer.hpp>
#include <silkworm/downloader/rpc/send_message_by_min_block.hpp>

namespace silkworm {

OutboundGetBlockBodies::OutboundGetBlockBodies() {}

int OutboundGetBlockBodies::sent_request() const { return sent_reqs_; }

void OutboundGetBlockBodies::execute(db::ROAccess, HeaderChain&, BodySequence& bs, SentryClient& sentry) {
    using namespace std::literals::chrono_literals;

    seconds_t timeout = 1s;
    int max_requests = 64;  // limit the number of requests sent per round

    do {
        time_point_t now = std::chrono::system_clock::now();

        auto [packet, penalizations, min_block] = bs.request_more_bodies(now, sentry.active_peers());

        if (packet.request.empty()) break;

        auto send_outcome = send_packet(sentry, packet, min_block, timeout);

        SILK_TRACE << "Bodies request sent (" << packet << "), received by " << send_outcome.peers_size() << " peer(s)";

        if (send_outcome.peers_size() == 0) {
            bs.request_nack(packet);
            break;
        }

        requested_bodies_ += packet.request.size();
        ++sent_reqs_;

        for (auto& penalization : penalizations) {
            SILK_TRACE << "Penalizing " << penalization;
            send_penalization(sentry, penalization, 1s);
        }

        --max_requests;
    } while (max_requests > 0);  // && packet != std::nullopt && receiving_peers != nullptr
}

sentry::SentPeers OutboundGetBlockBodies::send_packet(SentryClient& sentry, const GetBlockBodiesPacket66& packet_,
                                                      BlockNum min_block, seconds_t timeout) {
    auto request = std::make_unique<sentry::OutboundMessageData>();  // create header request

    request->set_id(sentry::MessageId::GET_BLOCK_BODIES_66);

    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, packet_);
    request->set_data(rlp_encoding.data(), rlp_encoding.length());  // copy

    SILK_TRACE << "Sending message OutboundGetBlockBodies with send_message_by_min_block, content:" << packet_;

    rpc::SendMessageByMinBlock rpc{min_block, std::move(request)};

    rpc.timeout(timeout);
    rpc.do_not_throw_on_failure();

    sentry.exec_remotely(rpc);

    if (!rpc.status().ok()) {
        SILK_TRACE << "Failure of rpc OutboundGetBlockBodies " << packet_ << ": " << rpc.status().error_message();
        return {};
    }

    sentry::SentPeers peers = rpc.reply();
    SILK_TRACE << "Received rpc result of OutboundGetBlockBodies reqId=" << packet_.requestId << ": "
               << std::to_string(peers.peers_size()) + " peer(s)";

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
    if (requested_bodies_ > 0)
        content << "OutboundGetBlockBodiesPackets " << requested_bodies_ << " bodies requested in " << sent_reqs_
                << " packets";
    else
        content << "-no message-";
    return content.str();
}

}  // namespace silkworm