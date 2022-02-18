/*
   Copyright 2021 The Silkworm Authors

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

#include "OutboundGetBlockHeaders.hpp"

#include <sstream>

#include <silkworm/common/log.hpp>
#include <silkworm/downloader/rpc/penalize_peer.hpp>
#include <silkworm/downloader/rpc/send_message_by_min_block.hpp>

namespace silkworm {

OutboundGetBlockHeaders::OutboundGetBlockHeaders(WorkingChain& wc, SentryClient& s)
    : working_chain_(wc), sentry_(s) {}

int OutboundGetBlockHeaders::sent_request() {
    return sent_reqs_;
}

void OutboundGetBlockHeaders::execute() {
    using namespace std::literals::chrono_literals;

    time_point_t now = std::chrono::system_clock::now();
    seconds_t timeout = 5s;
    int max_requests = 64;  // limit the number of requests sent per round

    // anchor extension
    do {
        auto [packet, penalizations] = working_chain_.request_more_headers(now, timeout);

        if (packet == std::nullopt) break;

        auto send_outcome = send_packet(*packet, timeout);

        packets_ += "o=" + std::to_string(std::get<BlockNum>(packet->request.origin)) + ",";  // todo: log level?
        SILK_TRACE << "Headers request sent (" << *packet << "), received by " << send_outcome.peers_size()
                     << " peer(s)";

        if (send_outcome.peers_size() == 0) {
            working_chain_.request_nack(*packet);
            break;
        }
        sent_reqs_++;

        for (auto& penalization : penalizations) {
            SILK_TRACE << "Penalizing " << penalization;
            send_penalization(penalization, 1s);
        }

        max_requests--;
    } while (max_requests > 0);  // && packet != std::nullopt && receiving_peers != nullptr

    // anchor collection
    auto packet = working_chain_.request_skeleton();

    if (packet != std::nullopt) {
        auto send_outcome = send_packet(*packet, timeout);
        sent_reqs_++;
        packets_ += "SK o=" + std::to_string(std::get<BlockNum>(packet->request.origin)) + ",";  // todo: log level?
        SILK_TRACE << "Headers skeleton request sent (" << *packet << "), received by " << send_outcome.peers_size()
                     << " peer(s)";
    }

    SILK_TRACE << "Sent message " << *this;
}

sentry::SentPeers OutboundGetBlockHeaders::send_packet(const GetBlockHeadersPacket66& packet_, seconds_t timeout) {
    // packet_ = packet;

    if (std::holds_alternative<Hash>(packet_.request.origin))
        throw std::logic_error("OutboundGetBlockHeaders expects block number not hash");

    BlockNum min_block = std::get<BlockNum>(packet_.request.origin);  // choose target peer
    if (!packet_.request.reverse) min_block += packet_.request.amount * packet_.request.skip;

    auto request = std::make_unique<sentry::OutboundMessageData>();  // create header request

    request->set_id(sentry::MessageId::GET_BLOCK_HEADERS_66);

    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, packet_);
    request->set_data(rlp_encoding.data(), rlp_encoding.length());  // copy

    SILK_TRACE << "Sending message OutboundGetBlockHeaders with send_message_by_min_block, content:" << packet_;

    rpc::SendMessageByMinBlock rpc{min_block, std::move(request)};

    rpc.timeout(timeout);
    rpc.do_not_throw_on_failure();

    sentry_.exec_remotely(rpc);

    if (!rpc.status().ok()) {
        SILK_TRACE << "Failure of rpc OutboundNewBlockHashes " << packet_ << ": " << rpc.status().error_message();
        return {};
    }

    sentry::SentPeers peers = rpc.reply();
    SILK_TRACE << "Received rpc result of OutboundGetBlockHeaders reqId=" << packet_.requestId << ": "
                 << std::to_string(peers.peers_size()) + " peer(s)";

    return peers;
}

void OutboundGetBlockHeaders::send_penalization(const PeerPenalization& penalization, seconds_t timeout) {
    rpc::PenalizePeer rpc{penalization.peerId, penalization.penalty};

    rpc.timeout(timeout);

    sentry_.exec_remotely(rpc);
}

std::string OutboundGetBlockHeaders::content() const {
    std::stringstream content;
    content << "GetBlockHeadersPackets " << packets_;
    return content.str();
}

}  // namespace silkworm