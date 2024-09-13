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

#include "inbound_block_bodies.hpp"

#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/sync/internals/body_sequence.hpp>
#include <silkworm/sync/sentry_client.hpp>

namespace silkworm {

InboundBlockBodies::InboundBlockBodies(ByteView data, PeerId peer_id)
    : peer_id_(std::move(peer_id)) {
    success_or_throw(rlp::decode(data, packet_));
    SILK_TRACE << "Received message " << *this;
}

void InboundBlockBodies::execute(db::ROAccess, HeaderChain&, BodySequence& bs, SentryClient& sentry) {
    SILK_TRACE << "Processing message " << *this;

    Penalty penalty = bs.accept_requested_bodies(packet_, peer_id_);

    if (penalty != Penalty::kNoPenalty) {
        SILK_TRACE << "Replying to " << identify(*this) << " with penalize_peer";
        SILK_TRACE << "Penalizing " << PeerPenalization{penalty, peer_id_};
        try {
            sentry.penalize_peer(peer_id_, penalty);
        } catch (const boost::system::system_error& se) {
            SILK_TRACE << "InboundBlockBodies failed penalize_peer error: " << se.what();
        }
    }
}

uint64_t InboundBlockBodies::reqId() const { return packet_.requestId; }

std::string InboundBlockBodies::content() const {
    std::stringstream content;
    log::prepare_for_logging(content);
    content << packet_;
    return content.str();
}

}  // namespace silkworm