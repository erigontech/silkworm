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

#include <silkworm/infra/common/log.hpp>
#include <silkworm/sync/internals/body_sequence.hpp>
#include <silkworm/sync/internals/header_chain.hpp>
#include <silkworm/sync/sentry_client.hpp>

namespace silkworm {

OutboundNewBlock::OutboundNewBlock(Blocks b, bool is_first_sync)
    : blocks_to_announce_{std::move(b)}, is_first_sync_{is_first_sync} {}

void OutboundNewBlock::execute(db::ROAccess, HeaderChain&, BodySequence&, SentryClient& sentry) {
    if (is_first_sync_) return;  // Don't announce blocks during first sync

    for (auto& block_ptr : blocks_to_announce_) {
        const BlockEx& block = *block_ptr;
        NewBlockPacket packet{block, block.td};  // NOLINT(cppcoreguidelines-slicing)
        auto peers = send_packet(sentry, std::move(packet));

        // no peers available
        if (peers.empty()) break;
    }
}

Bytes OutboundNewBlock::message_data() const {
    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, packet_);
    return rlp_encoding;
}

std::vector<PeerId> OutboundNewBlock::send_packet(SentryClient& sentry, NewBlockPacket packet) {
    SILK_TRACE << "Sending message OutboundNewBlock (announcements) with send_message_to_random_peers, content:" << packet;

    packet_ = std::move(packet);
    auto peers = sentry.send_message_to_random_peers(*this, kMaxPeers);
    sent_packets_++;

    SILK_TRACE << "Received sentry result of OutboundNewBlock: " << std::to_string(peers.size()) + " peer(s)";

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
