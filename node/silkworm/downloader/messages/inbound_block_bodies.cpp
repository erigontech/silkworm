/*
   Copyright 2021-2022 The Silkworm Authors

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

#include <silkworm/common/log.hpp>

namespace silkworm {

InboundBlockBodies::InboundBlockBodies(const sentry::InboundMessage& msg, WorkingChain& wc, SentryClient& s)
    : InboundMessage(), working_chain_(wc), sentry_(s) {
    if (msg.id() != sentry::MessageId::BLOCK_BODIES_66)
        throw std::logic_error("InboundBlockBodies received wrong InboundMessage");

    peerId_ = string_from_H512(msg.peer_id());

    ByteView data = string_view_to_byte_view(msg.data());  // copy for consumption
    rlp::success_or_throw(rlp::decode(data, packet_));

    SILK_TRACE << "Received message " << *this;
}

void InboundBlockBodies::execute() {
    using namespace std;

    SILK_TRACE << "Processing message " << *this;

    // todo: implement
}

uint64_t InboundBlockBodies::reqId() const { return packet_.requestId; }

std::string InboundBlockBodies::content() const {
    std::stringstream content;
    content << packet_;
    return content.str();
}

}  // namespace silkworm