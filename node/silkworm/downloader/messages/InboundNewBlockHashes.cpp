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

#include "InboundNewBlockHashes.hpp"

#include <algorithm>

#include <silkworm/common/log.hpp>
#include <silkworm/downloader/internals/random_number.hpp>
#include <silkworm/downloader/packets/RLPEth66PacketCoding.hpp>
#include <silkworm/downloader/rpc/send_message_by_id.hpp>

namespace silkworm {

InboundNewBlockHashes::InboundNewBlockHashes(const sentry::InboundMessage& msg, WorkingChain& wc, SentryClient& s)
    : InboundMessage(), working_chain_(wc), sentry_(s) {
    if (msg.id() != sentry::MessageId::NEW_BLOCK_HASHES_66)
        throw std::logic_error("InboundNewBlockHashes received wrong InboundMessage");

    reqId_ = RANDOM_NUMBER.generate_one();  // for trace purposes

    peerId_ = string_from_H512(msg.peer_id());

    ByteView data = string_view_to_byte_view(msg.data());  // copy for consumption
    rlp::success_or_throw(rlp::decode(data, packet_));

    SILK_TRACE << "Received message " << *this;
}

void InboundNewBlockHashes::execute() {
    using namespace std;

    SILK_TRACE << "Processing message " << *this;

    // todo: Erigon apparently processes this message even if it is not in a fetching phase BUT is in request-chaining
    // mode - do we need the same?

    BlockNum max = working_chain_.top_seen_block_height();

    for (size_t i = 0; i < packet_.size(); i++) {
        Hash hash = packet_[i].hash;

        // save announcement
        working_chain_.save_external_announce(hash);
        if (working_chain_.has_link(hash)) continue;

        // request header
        GetBlockHeadersPacket66 reply;
        reply.requestId = RANDOM_NUMBER.generate_one();
        reply.request.origin = hash;
        reply.request.amount = 1;
        reply.request.skip = 0;
        reply.request.reverse = false;

        Bytes rlp_encoding;
        rlp::encode(rlp_encoding, reply);

        auto msg_reply = std::make_unique<sentry::OutboundMessageData>();
        msg_reply->set_id(sentry::MessageId::GET_BLOCK_HEADERS_66);
        msg_reply->set_data(rlp_encoding.data(), rlp_encoding.length());  // copy

        // send msg_reply
        SILK_TRACE << "Replying to " << identify(*this) << " with send_message_by_id, content: " << reply;
        rpc::SendMessageById rpc(peerId_, std::move(msg_reply));
        rpc.do_not_throw_on_failure();

        sentry_.exec_remotely(rpc);

        [[maybe_unused]] sentry::SentPeers peers = rpc.reply();
        SILK_TRACE << "Received rpc result of " << identify(*this) << ": "
                     << std::to_string(peers.peers_size()) + " peer(s)";

        // calculate top seen block height
        max = std::max(max, packet_[i].number);
    }

    working_chain_.top_seen_block_height(max);
}

uint64_t InboundNewBlockHashes::reqId() const { return reqId_; }

std::string InboundNewBlockHashes::content() const {
    std::stringstream content;
    content << packet_;
    return content.str();
}

}  // namespace silkworm