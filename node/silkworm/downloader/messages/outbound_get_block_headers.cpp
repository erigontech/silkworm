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

#include <silkworm/common/log.hpp>
#include <silkworm/downloader/rpc/penalize_peer.hpp>
#include <silkworm/downloader/rpc/send_message_by_min_block.hpp>

namespace silkworm {

OutboundGetBlockHeaders::OutboundGetBlockHeaders(size_t mr, uint64_t ap) : max_reqs_{mr}, active_peers_{ap} {}

size_t OutboundGetBlockHeaders::sent_requests() const { return sent_reqs_; }
size_t OutboundGetBlockHeaders::nack_requests() const { return nack_reqs_; }

void OutboundGetBlockHeaders::execute(db::ROAccess, HeaderChain& hc, BodySequence&, SentryClient& sentry) {
    using namespace std::literals::chrono_literals;

    time_point_t now = std::chrono::system_clock::now();
    seconds_t request_timeout = 30s;
    seconds_t response_timeout = 1s;

    // anchor extension
    do {
        auto [packet, penalizations] = hc.anchor_extension_request(now, request_timeout);

        if (packet == std::nullopt) break;

        auto send_outcome = send_packet(sentry, *packet, response_timeout);

        packets_ += "o=" + std::to_string(std::get<BlockNum>(packet->request.origin)) + ",";
        SILK_TRACE << "Headers request sent (OutboundGetBlockHeaders/" << *packet << "), received by " << send_outcome.peers_size()
                   << "/" << active_peers_ << " peer(s)";

        if (send_outcome.peers_size() == 0) {
            hc.request_nack(*packet);
            ++nack_reqs_;
            break;
        }

        requested_headers_ += packet->request.amount;
        ++sent_reqs_;

        for (auto& penalization : penalizations) {
            SILK_TRACE << "Penalizing " << penalization;
            send_penalization(sentry, penalization, 1s);
        }

    } while (sent_reqs_ < max_reqs_);  // && packet != std::nullopt && receiving_peers != nullptr

    // anchor collection
    auto packet = hc.anchor_skeleton_request(now, request_timeout);

    if (packet != std::nullopt) {
        auto send_outcome = send_packet(sentry, *packet, response_timeout);
        sent_reqs_++;
        requested_headers_ += packet->request.amount;
        packets_ += "SK o=" + std::to_string(std::get<BlockNum>(packet->request.origin)) + ",";
        SILK_TRACE << "Headers skeleton request sent (" << *packet << "), received by " << send_outcome.peers_size()
                   << "/" << active_peers_ << " peer(s)";
    }

    if (!packets_.empty()) {
        SILK_TRACE << "Sent message " << *this;
    }
}

sentry::SentPeers OutboundGetBlockHeaders::send_packet(SentryClient& sentry,
                                                       const GetBlockHeadersPacket66& packet_, seconds_t timeout) {
    if (std::holds_alternative<Hash>(packet_.request.origin))
        throw std::logic_error("OutboundGetBlockHeaders expects block number not hash");

    if (std::get<BlockNum>(packet_.request.origin) == 0 ||
        packet_.request.amount == 0)
        throw std::logic_error("OutboundGetBlockHeaders expects block number > 0 and amount > 0");

    BlockNum min_block = std::get<BlockNum>(packet_.request.origin);  // choose target peer
    if (!packet_.request.reverse) min_block += packet_.request.amount * packet_.request.skip;

    auto request = std::make_unique<sentry::OutboundMessageData>();  // create header request

    request->set_id(sentry::MessageId::GET_BLOCK_HEADERS_66);

    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, packet_);
    request->set_data(rlp_encoding.data(), rlp_encoding.length());  // copy

    // SILK_TRACE << "Sending message OutboundGetBlockHeaders with send_message_by_min_block, content:" << packet_;

    rpc::SendMessageByMinBlock rpc{min_block, std::move(request)};

    rpc.timeout(timeout);
    rpc.do_not_throw_on_failure();

    sentry.exec_remotely(rpc);

    if (!rpc.status().ok()) {
        SILK_TRACE << "Failure of rpc OutboundGetBlockHeaders " << packet_ << ": " << rpc.status().error_message();
        return {};
    }

    sentry::SentPeers peers = rpc.reply();
    // SILK_TRACE << "Received rpc result of OutboundGetBlockHeaders reqId=" << packet_.requestId << ": "
    //            << std::to_string(peers.peers_size()) + " peer(s)";

    return peers;
}

void OutboundGetBlockHeaders::send_penalization(SentryClient& sentry, const PeerPenalization& penalization, seconds_t timeout) {
    rpc::PenalizePeer rpc{penalization.peerId, penalization.penalty};

    rpc.timeout(timeout);

    sentry.exec_remotely(rpc);
}

std::string OutboundGetBlockHeaders::content() const {
    std::stringstream content;
    log::prepare_for_logging(content);
    if (!packets_.empty())
        content << "GetBlockHeadersPackets " << packets_;
    else
        content << "-no message-";
    return content.str();
}

}  // namespace silkworm