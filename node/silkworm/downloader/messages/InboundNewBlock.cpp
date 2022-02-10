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

#include "InboundNewBlock.hpp"

#include <algorithm>

#include <silkworm/common/cast.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/downloader/internals/random_number.hpp>
#include <silkworm/downloader/rpc/send_message_by_id.hpp>

namespace silkworm {

InboundNewBlock::InboundNewBlock(const sentry::InboundMessage& msg, WorkingChain& wc, SentryClient& s)
    : InboundMessage(), working_chain_(wc), sentry_(s) {
    if (msg.id() != sentry::MessageId::NEW_BLOCK_66)
        throw std::logic_error("InboundNewBlock received wrong InboundMessage");

    reqId_ = RANDOM_NUMBER.generate_one();  // for trace purposes

    peerId_ = string_from_H512(msg.peer_id());

    ByteView data = string_view_to_byte_view(msg.data());  // copy for consumption
    rlp::success_or_throw(rlp::decode(data, packet_));

    SILK_TRACE << "Received message " << *this;
}

void InboundNewBlock::execute() {
    // todo: Erigon header-downloader apparently processes this message even if it is not in a fetching phase - do we
    // need the same?

    // todo: implement in the block-downloader
}

uint64_t InboundNewBlock::reqId() const { return reqId_; }

std::string InboundNewBlock::content() const {
    std::stringstream content;
    content << packet_;
    return content.str();
}

}  // namespace silkworm
