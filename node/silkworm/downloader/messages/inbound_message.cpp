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

#include "inbound_message.hpp"

#include <iostream>

#include <silkworm/common/log.hpp>

#include "inbound_block_bodies.hpp"
#include "inbound_block_headers.hpp"
#include "inbound_get_block_bodies.hpp"
#include "inbound_get_block_headers.hpp"
#include "inbound_new_block.hpp"
#include "inbound_new_block_hashes.hpp"

namespace silkworm {

std::shared_ptr<InboundMessage> InboundMessage::make(const sentry::InboundMessage& raw_message) {
    std::shared_ptr<InboundMessage> message;
    if (raw_message.id() == sentry::MessageId::GET_BLOCK_HEADERS_66)
        message = std::make_shared<InboundGetBlockHeaders>(raw_message);
    else if (raw_message.id() == sentry::MessageId::GET_BLOCK_BODIES_66)
        message = std::make_shared<InboundGetBlockBodies>(raw_message);
    else if (raw_message.id() == sentry::MessageId::NEW_BLOCK_HASHES_66)
        message = std::make_shared<InboundNewBlockHashes>(raw_message);
    else if (raw_message.id() == sentry::MessageId::NEW_BLOCK_66)
        message = std::make_shared<InboundNewBlock>(raw_message);
    else if (raw_message.id() == sentry::MessageId::BLOCK_HEADERS_66)
        message = std::make_shared<InboundBlockHeaders>(raw_message);
    else if (raw_message.id() == sentry::MessageId::BLOCK_BODIES_66)
        message = std::make_shared<InboundBlockBodies>(raw_message);
    else
        log::Warning("HeaderStage") << "InboundMessage " << sentry::MessageId_Name(raw_message.id())
                                    << " received but ignored";
    return message;
}

std::ostream& operator<<(std::ostream& os, const silkworm::InboundMessage& msg) {
    os << msg.name() << " content: " << msg.content();
    return os;
}

std::string identify(const silkworm::InboundMessage& message) {
    return message.name() + " reqId=" + std::to_string(message.reqId());
}

}  // namespace silkworm
