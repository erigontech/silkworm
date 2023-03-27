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

#include "hello_message.hpp"

#include <sstream>
#include <stdexcept>

#include <silkworm/core/common/as_range.hpp>
#include <silkworm/core/rlp/decode.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>

namespace silkworm::sentry::rlpx::auth {

using common::Message;

const uint8_t HelloMessage::kId = 0;
const uint8_t HelloMessage::kProtocolVersion = 5;

size_t length(const HelloMessage::Capability& capability) {
    return rlp::length(capability.name_bytes, capability.version);
}

void encode(Bytes& to, const HelloMessage::Capability& capability) {
    rlp::encode(to, capability.name_bytes, capability.version);
}

DecodingResult decode(ByteView& from, HelloMessage::Capability& to) noexcept {
    return rlp::decode(from, to.name_bytes, to.version);
}

bool HelloMessage::contains_capability(const Capability& capability) const {
    auto it = as_range::find_if(
        capabilities_,
        [&capability](const Capability& c) -> bool {
            return ((c.name_bytes == capability.name_bytes) && (c.version == capability.version));
        });
    return (it != capabilities_.end());
}

std::string HelloMessage::Capability::to_string() const {
    std::ostringstream stream;
    stream << name() << "/" << static_cast<int>(version);
    return stream.str();
}

std::string HelloMessage::capabilities_description() {
    std::ostringstream stream;
    for (auto& capability : capabilities_) {
        stream << capability.to_string() << ";";
    }
    return stream.str();
}

Bytes HelloMessage::rlp_encode() const {
    Bytes data;
    rlp::encode(
        data,
        protocol_version_,
        client_id_bytes_,
        capabilities_,
        listen_port_,
        node_id_bytes_);
    return data;
}

HelloMessage HelloMessage::rlp_decode(ByteView data) {
    HelloMessage message;
    success_or_throw(rlp::decode(
                         data,
                         message.protocol_version_,
                         message.client_id_bytes_,
                         message.capabilities_,
                         message.listen_port_,
                         message.node_id_bytes_),
                     "Failed to decode HelloMessage RLP");
    return message;
}

Message HelloMessage::to_message() const {
    return Message{kId, rlp_encode()};
}

HelloMessage HelloMessage::from_message(const Message& message) {
    return rlp_decode(message.data);
}

}  // namespace silkworm::sentry::rlpx::auth
