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

#include "inbound_new_block_hashes.hpp"

#include <algorithm>

#include <silkworm/core/common/cast.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/sync/internals/body_sequence.hpp>
#include <silkworm/sync/internals/header_chain.hpp>
#include <silkworm/sync/internals/random_number.hpp>
#include <silkworm/sync/packets/rlp_eth66_packet_coding.hpp>
#include <silkworm/sync/rpc/send_message_by_id.hpp>

namespace silkworm {

InboundNewBlockHashes::InboundNewBlockHashes(const sentry::InboundMessage& msg) {
    if (msg.id() != sentry::MessageId::NEW_BLOCK_HASHES_66)
        throw std::logic_error("InboundNewBlockHashes received wrong InboundMessage");

    reqId_ = RANDOM_NUMBER.generate_one();  // for trace purposes

    peerId_ = bytes_from_H512(msg.peer_id());

    ByteView data = string_view_to_byte_view(msg.data());  // copy for consumption
    success_or_throw(rlp::decode(data, packet_));

    SILK_TRACE << "Received message " << *this;
}

void InboundNewBlockHashes::execute(db::ROAccess, HeaderChain& hc, BodySequence&, SentryClient& sentry) {
    using namespace std;

    SILK_TRACE << "Processing message " << *this;

    BlockNum max = hc.top_seen_block_height();

    for (size_t i = 0; i < packet_.size(); i++) {
        Hash hash = packet_[i].hash;

        // calculate top seen block height
        max = std::max(max, packet_[i].number);

        // save announcement
        auto packet = hc.save_external_announce(hash);
        if (!packet) continue;

        // request header
        Bytes rlp_encoding;
        rlp::encode(rlp_encoding, *packet);

        auto msg_reply = std::make_unique<sentry::OutboundMessageData>();
        msg_reply->set_id(sentry::MessageId::GET_BLOCK_HEADERS_66);
        msg_reply->set_data(rlp_encoding.data(), rlp_encoding.length());  // copy

        // send msg_reply
        SILK_TRACE << "Replying to " << identify(*this) << " requesting header with send_message_by_id, content: " << *packet;
        rpc::SendMessageById rpc(peerId_, std::move(msg_reply));
        rpc.do_not_throw_on_failure();

        sentry.exec_remotely(rpc);

        [[maybe_unused]] sentry::SentPeers peers = rpc.reply();
        SILK_TRACE << "Received rpc result of " << identify(*this) << ": "
                   << std::to_string(peers.peers_size()) + " peer(s)";
    }

    hc.top_seen_block_height(max);
}

uint64_t InboundNewBlockHashes::reqId() const { return reqId_; }

std::string InboundNewBlockHashes::content() const {
    std::stringstream content;
    log::prepare_for_logging(content);
    content << packet_;
    return content.str();
}

}  // namespace silkworm