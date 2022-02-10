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

#include "InboundGetBlockHeaders.hpp"

#include <silkworm/common/cast.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/downloader/internals/header_retrieval.hpp>
#include <silkworm/downloader/packets/BlockHeadersPacket.hpp>
#include <silkworm/downloader/rpc/send_message_by_id.hpp>

namespace silkworm {

InboundGetBlockHeaders::InboundGetBlockHeaders(const sentry::InboundMessage& msg, Db::ReadOnlyAccess db,
                                               SentryClient& sentry)
    : InboundMessage(), db_(db), sentry_(sentry) {
    if (msg.id() != sentry::MessageId::GET_BLOCK_HEADERS_66) {
        throw std::logic_error("InboundGetBlockHeaders received wrong InboundMessage");
    }

    peerId_ = string_from_H512(msg.peer_id());

    ByteView data = string_view_to_byte_view(msg.data());
    rlp::success_or_throw(rlp::decode(data, packet_));

    SILK_TRACE << "Received message " << *this;
}

void InboundGetBlockHeaders::execute() {
    using namespace std;

    SILK_TRACE << "Processing message " << *this;

    HeaderRetrieval header_retrieval(db_);

    BlockHeadersPacket66 reply;
    reply.requestId = packet_.requestId;
    if (holds_alternative<Hash>(packet_.request.origin)) {
        reply.request = header_retrieval.recover_by_hash(get<Hash>(packet_.request.origin), packet_.request.amount,
                                                         packet_.request.skip, packet_.request.reverse);
    } else {
        reply.request =
            header_retrieval.recover_by_number(get<BlockNum>(packet_.request.origin), packet_.request.amount,
                                               packet_.request.skip, packet_.request.reverse);
    }

    if (reply.request.empty()) {
        log::Trace() << "[WARNING] Not replying to " << identify(*this) << ", no headers found";
        return;
    }

    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, reply);

    auto msg_reply = std::make_unique<sentry::OutboundMessageData>();
    msg_reply->set_id(sentry::MessageId::BLOCK_HEADERS_66);
    msg_reply->set_data(rlp_encoding.data(), rlp_encoding.length());  // copy

    SILK_TRACE << "Replying to " << identify(*this) << " using send_message_by_id with "
                        << reply.request.size() << " headers";

    rpc::SendMessageById rpc{peerId_, std::move(msg_reply)};
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

uint64_t InboundGetBlockHeaders::reqId() const { return packet_.requestId; }

std::string InboundGetBlockHeaders::content() const {
    std::stringstream content;
    content << packet_;
    return content.str();
}

}  // namespace silkworm
