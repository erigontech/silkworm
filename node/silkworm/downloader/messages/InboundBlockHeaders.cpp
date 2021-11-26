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

#include "InboundBlockHeaders.hpp"

#include <silkworm/common/cast.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/downloader/rpc/PeerMinBlock.hpp>
#include <silkworm/downloader/rpc/PenalizePeer.hpp>

namespace silkworm {

InboundBlockHeaders::InboundBlockHeaders(const sentry::InboundMessage& msg, WorkingChain& wc, SentryClient& s)
    : InboundMessage(), working_chain_(wc), sentry_(s) {
    if (msg.id() != sentry::MessageId::BLOCK_HEADERS_66)
        throw std::logic_error("InboundBlockHeaders received wrong InboundMessage");

    peerId_ = string_from_H512(msg.peer_id());

    ByteView data = string_view_to_byte_view(msg.data());  // copy for consumption
    rlp::success_or_throw(rlp::decode(data, packet_));

    SILKWORM_LOG(LogLevel::Trace) << "Received message " << *this << "\n";
}

void InboundBlockHeaders::execute() {
    using namespace std;

    BlockNum highestBlock = 0;
    for (BlockHeader& header : packet_.request) {
        highestBlock = std::max(highestBlock, header.number);
    }

    auto [penalty, requestMoreHeaders] = working_chain_.accept_headers(packet_.request, peerId_);

    // Erigon here calls request_more_headers(). Do we have to do the same? What if header downloader is not in a
    // forward phase? todo: decide if we need to call request_more_headers() here
    /* If we need to implement as Erigon does:
    if (penalty == Penalty::NoPenalty && requestMoreHeaders) {
        OutboundGetBlockHeaders message(working_chain_, sentry_);
        message.execute();
    }
    */
    SILKWORM_LOG(LogLevel::Warn) << "Handling of " << identify(*this) << " is incomplete\n";

    if (penalty != Penalty::NoPenalty) {
        SILKWORM_LOG(LogLevel::Trace) << "Replying to " << identify(*this) << " with penalize_peer\n";
        rpc::PenalizePeer penalize_peer(peerId_, penalty);
        penalize_peer.do_not_throw_on_failure();
        sentry_.exec_remotely(penalize_peer);
    }

    SILKWORM_LOG(LogLevel::Trace) << "Replying to " << identify(*this) << " with peer_min_block\n";
    rpc::PeerMinBlock rpc(peerId_, highestBlock);
    rpc.do_not_throw_on_failure();
    sentry_.exec_remotely(rpc);

    if (!rpc.status().ok()) {
        SILKWORM_LOG(LogLevel::Trace) << "Failure of the replay to rpc " << identify(*this) << ": "
                                      << rpc.status().error_message() + "\n";
    }

}

uint64_t InboundBlockHeaders::reqId() const { return packet_.requestId; }

std::string InboundBlockHeaders::content() const {
    std::stringstream content;
    content << packet_;
    return content.str();
}

}  // namespace silkworm