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

#include "InboundGetBlockBodies.hpp"

#include <silkworm/common/log.hpp>
#include <silkworm/downloader/internals/body_retrieval.hpp>
#include <silkworm/downloader/packets/BlockBodiesPacket.hpp>
#include <silkworm/downloader/rpc/send_message_by_id.hpp>

namespace silkworm {

InboundGetBlockBodies::InboundGetBlockBodies(const sentry::InboundMessage& msg, Db::ReadOnlyAccess db, SentryClient& s)
    : InboundMessage(), db_(db), sentry_(s) {
    if (msg.id() != sentry::MessageId::GET_BLOCK_BODIES_66) {
        throw std::logic_error("InboundGetBlockBodies received wrong InboundMessage");
    }

    peerId_ = string_from_H512(msg.peer_id());

    ByteView data = string_view_to_byte_view(msg.data());
    rlp::success_or_throw(rlp::decode(data, packet_));

    SILK_TRACE << "Received message " << *this;
}

/*
 // ReplyBlockBodiesRLP is the eth/66 version of SendBlockBodiesRLP.
func (p *Peer) ReplyBlockBodiesRLP(id uint64, bodies []rlp.RawValue) error {
        // Not packed into BlockBodiesPacket to avoid RLP decoding
        return p2p.Send(p.rw, BlockBodiesMsg, BlockBodiesRLPPacket66{
                RequestId:            id,
                BlockBodiesRLPPacket: bodies,
        })
}
 */
void InboundGetBlockBodies::execute() {
    using namespace std;

    SILK_TRACE << "Processing message " << *this;

    BodyRetrieval body_retrieval(db_);

    BlockBodiesPacket66 reply;
    reply.requestId = packet_.requestId;
    reply.request = body_retrieval.recover(packet_.request);

    if (reply.request.empty()) {
        log::Trace() << "[WARNING] Not replying to " << identify(*this) << ", no blocks found";
        return;
    }

    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, reply);

    auto msg_reply = std::make_unique<sentry::OutboundMessageData>();
    msg_reply->set_id(sentry::MessageId::BLOCK_BODIES_66);
    msg_reply->set_data(rlp_encoding.data(), rlp_encoding.length());  // copy

    SILK_TRACE << "Replying to " << identify(*this) << " using send_message_by_id with "
                 << reply.request.size() << " bodies";

    rpc::SendMessageById rpc(peerId_, std::move(msg_reply));
    rpc.do_not_throw_on_failure();
    sentry_.exec_remotely(rpc);

    if (rpc.status().ok()) {
        sentry::SentPeers peers = rpc.reply();
        SILK_TRACE << "Received rpc result of " << identify(*this) << ": "
                     << std::to_string(peers.peers_size()) + " peer(s)";
    }
    else {
        SILK_TRACE << "Failure of rpc " << identify(*this) << ": "
                     << rpc.status().error_message();
    }

}

uint64_t InboundGetBlockBodies::reqId() const { return packet_.requestId; }

std::string InboundGetBlockBodies::content() const {
    std::stringstream content;
    content << packet_;
    return content.str();
}

}  // namespace silkworm
