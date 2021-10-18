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
    rlp::DecodingResult err = rlp::decode(data, packet_);
    if (err != rlp::DecodingResult::kOk) throw rlp::rlp_error("rlp decoding error decoding BlockHeaders");

    SILKWORM_LOG(LogLevel::Info) << "Received message " << *this << "\n";
}

/* blockHeaders66 processing from Erigon
 if segments, penalty, err := cs.Hd.SplitIntoSegments(headersRaw, headers); err == nil {
     if penalty == headerdownload.NoPenalty {
         var canRequestMore bool
         for _, segment := range segments {
             newBlock = false;
             requestMore := cs.Hd.ProcessSegment(segment, newBlock, string(gointerfaces.ConvertH512ToBytes(in.PeerId)))
             canRequestMore = canRequestMore || requestMore
         }

         if canRequestMore {
                 currentTime := uint64(time.Now().Unix())
                 req, penalties := cs.Hd.RequestMoreHeaders(currentTime)
                 if req != nil {
                     if peer := cs.SendHeaderRequest(ctx, req); peer != nil {
                         timeOut = 5;
                         cs.Hd.SentRequest(req, currentTime, timeOut)
                         log.Debug("Sent request", "height", req.Number)
                     }
                 }
                 cs.Penalize(ctx, penalties)
             }
     } else {
         outreq := proto_sentry.PenalizePeerRequest{
             PeerId:  in.PeerId,
             Penalty: proto_sentry.PenaltyKind_Kick,
         }
         if _, err1 := sentry.PenalizePeer(ctx, &outreq, &grpc.EmptyCallOption{}); err1 != nil {
             log.Error("Could not send penalty", "err", err1)
         }
     }
 } else {
     return fmt.Errorf("singleHeaderAsSegment failed: %v", err)
 }
 outreq := proto_sentry.PeerMinBlockRequest{
     PeerId:   in.PeerId,
     MinBlock: heighestBlock,
 }
 */

void InboundBlockHeaders::execute() {
    using namespace std;

    // todo: PRIO - Erigon apparently processes this message even if it is not in a fetching phase - do we need the
    // same?

    BlockNum highestBlock = 0;
    for (BlockHeader& header : packet_.request) {
        highestBlock = std::max(highestBlock, header.number);
    }

    auto [penalty, requestMoreHeaders] =
        working_chain_.accept_headers(packet_.request, peerId_);  // todo: provide WorkingChain as messages member

    // Erigon here calls request_more_headers(). Do we have to do the same? What if header downloader is not in a
    // forward phase? todo: take a decision here!
    /* If we need to implement as Erigon does:
    if (penalty == Penalty::NoPenalty && requestMoreHeaders) {
        OutboundGetBlockHeaders message(working_chain_, sentry_);
        message.execute();
    }
    */
    SILKWORM_LOG(LogLevel::Warn) << "Handling of " << identify(*this) << " is incomplete\n";

    if (penalty != Penalty::NoPenalty) {
        SILKWORM_LOG(LogLevel::Info) << "Replying to " << identify(*this) << " with penalize_peer\n";
        rpc::PenalizePeer penalize_peer(peerId_, penalty);
        sentry_.exec_remotely(penalize_peer);
    }

    SILKWORM_LOG(LogLevel::Info) << "Replying to " << identify(*this) << " with peer_min_block\n";
    rpc::PeerMinBlock peer_min_block(peerId_, highestBlock);
    sentry_.exec_remotely(peer_min_block);
}

uint64_t InboundBlockHeaders::reqId() const { return packet_.requestId; }

std::string InboundBlockHeaders::content() const {
    std::stringstream content;
    content << packet_;
    return content.str();
}

}  // namespace silkworm