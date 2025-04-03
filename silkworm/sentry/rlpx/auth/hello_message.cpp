// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "hello_message.hpp"

#include <algorithm>
#include <sstream>
#include <stdexcept>

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>

namespace silkworm::sentry::rlpx::auth {

const uint8_t HelloMessage::kId = 0;
const uint8_t HelloMessage::kProtocolVersion = 5;

static size_t length(const HelloMessage::Capability& capability) {
    return rlp::length(capability.name_bytes, capability.version);
}

static void encode(Bytes& to, const HelloMessage::Capability& capability) {
    rlp::encode(to, capability.name_bytes, capability.version);
}

static DecodingResult decode(ByteView& from, HelloMessage::Capability& to, rlp::Leftover mode) noexcept {
    return rlp::decode(from, mode, to.name_bytes, to.version);
}

bool HelloMessage::contains_capability(const Capability& capability) const {
    auto it = std::ranges::find_if(
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

std::string HelloMessage::capabilities_to_string() {
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
    auto result = rlp::decode(
        data,
        rlp::Leftover::kProhibit,
        message.protocol_version_,
        message.client_id_bytes_,
        message.capabilities_,
        message.listen_port_,
        message.node_id_bytes_);
    if (!result && (result.error() != DecodingError::kUnexpectedListElements)) {
        throw DecodingException(result.error(), "Failed to decode HelloMessage RLP");
    }
    return message;
}

Message HelloMessage::to_message() const {
    return Message{kId, rlp_encode()};
}

HelloMessage HelloMessage::from_message(const Message& message) {
    return rlp_decode(message.data);
}

}  // namespace silkworm::sentry::rlpx::auth
