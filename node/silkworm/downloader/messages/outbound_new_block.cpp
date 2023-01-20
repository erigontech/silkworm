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

#include "outbound_new_block.hpp"

#include <silkworm/common/log.hpp>
#include <silkworm/downloader/rpc/send_message_to_random_peers.hpp>

namespace silkworm {

OutboundNewBlock::OutboundNewBlock(Blocks b, bool f): blocks_to_announce_{std::move(b)}, is_first_sync_{f} {}

void OutboundNewBlock::execute(db::ROAccess, HeaderChain&, BodySequence&, SentryClient& sentry) {
    using namespace std::literals::chrono_literals;

    if (is_first_sync_) return;  // Don't announce blocks during first sync

    for (auto& block_ptr: blocks_to_announce_) {
        const BlockEx& block = *block_ptr;
        NewBlockPacket packet{{block, block.header}, block.td};
        auto peers = send_packet(sentry, packet, 1s);

        if (peers.peers_size() == 0) break;  // no peer available
    }
}

sentry::SentPeers OutboundNewBlock::send_packet(SentryClient& sentry, const NewBlockPacket& packet, seconds_t timeout) {
    auto request = std::make_unique<sentry::OutboundMessageData>();  // create request

    request->set_id(sentry::MessageId::NEW_BLOCK_66);

    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, packet);
    request->set_data(rlp_encoding.data(), rlp_encoding.length());  // copy

    SILK_TRACE << "Sending message OutboundNewBlock (announcements) with send_message_to_random_peers, content:" << packet;

    rpc::SendMessageToRandomPeers rpc{kMaxPeers, std::move(request)};

    rpc.timeout(timeout);
    rpc.do_not_throw_on_failure();

    sentry.exec_remotely(rpc);

    if (!rpc.status().ok()) {
        SILK_TRACE << "Failure of rpc OutboundNewBlock " << packet << ": " << rpc.status().error_message();
        return {};
    }

    sent_packets_++;

    sentry::SentPeers peers = rpc.reply();
    SILK_TRACE << "Received rpc result of OutboundNewBlock: " << std::to_string(peers.peers_size()) + " peer(s)";

    return peers;
}

std::string OutboundNewBlock::content() const {
    if (sent_packets_ == 0) return "- no block announcements -";
    std::stringstream content;
    log::prepare_for_logging(content);
    content << sent_packets_ << " block announcements";
    return content.str();
}

}  // namespace silkworm
