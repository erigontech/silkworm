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
#include <silkworm/downloader/header_downloader.hpp>
#include <silkworm/downloader/packets/RLPEth66PacketCoding.hpp>
#include <silkworm/downloader/rpc/SendMessageByMinBlock.hpp>

namespace silkworm {

OutboundGetBlockHeaders::OutboundGetBlockHeaders(WorkingChain& wc, SentryClient& s): working_chain_(wc), sentry_(s) {}

void OutboundGetBlockHeaders::execute() {
    // see TG sendHeaderRequest

    auto packet = working_chain_.headers_forward(); // ask for headers
    if (!packet) return;
    packet_ = *packet;

    if (std::holds_alternative<Hash>(packet_.request.origin))
        throw std::logic_error("OutboundGetBlockHeaders expects block number not hash");    // todo: check!

    BlockNum min_block = std::get<BlockNum>(packet_.request.origin); // choose target peer
    if (!packet_.request.reverse)
        min_block += packet_.request.amount * packet_.request.skip;

    auto msg_reply = std::make_unique<sentry::OutboundMessageData>(); // create header request

    msg_reply->set_id(sentry::MessageId::GET_BLOCK_HEADERS_66);

    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, packet_);
    msg_reply->set_data(rlp_encoding.data(), rlp_encoding.length()); // copy

    SILKWORM_LOG(LogLevel::Info) << "Requesting " << identify(*this) << " with send_message_by_min_block\n";
    rpc::SendMessageByMinBlock rpc{min_block, std::move(msg_reply)};
    sentry_.exec_remotely(rpc);

    [[maybe_unused]] sentry::SentPeers peers = rpc.reply();
    SILKWORM_LOG(LogLevel::Info) << "Received rpc result of " << identify(*this) << ": " << std::to_string(peers.peers_size()) + " peer(s)\n";
}

uint64_t OutboundGetBlockHeaders::reqId() const {
    return packet_.requestId;
}

std::string OutboundGetBlockHeaders::content() const {
    std::stringstream content;
    content << packet_;
    return content.str();
}

}