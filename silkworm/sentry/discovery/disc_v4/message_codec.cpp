// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "message_codec.hpp"

#include <cstddef>
#include <cstring>
#include <stdexcept>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/sentry/common/crypto/ecdsa_signature.hpp>

#include "common/packet_type.hpp"

namespace silkworm::sentry::discovery::disc_v4 {

#pragma pack(push)
#pragma pack(1)
struct Packet {
    uint8_t hash[32]{};
    uint8_t signature[65]{};
    uint8_t type{};
    uint8_t data[1]{};
};
#pragma pack(pop)

using namespace crypto;

Bytes MessageCodec::encode(const Message& message, ByteView private_key) {
    Bytes packet_data(sizeof(Packet) + message.data.size() - 1, 0);
    auto packet = reinterpret_cast<Packet*>(packet_data.data());

    packet->type = message.id;
    memcpy(packet->data, message.data.data(), message.data.size());

    auto type_and_data_hash = keccak256(ByteView(packet_data).substr(offsetof(Packet, type)));
    Bytes signature = ecdsa_signature::sign_recoverable(ByteView(type_and_data_hash.bytes), private_key);
    memcpy(packet->signature, signature.data(), signature.size());

    auto hash = keccak256(ByteView(packet_data).substr(offsetof(Packet, signature)));
    memcpy(packet->hash, hash.bytes, sizeof(hash.bytes));

    return packet_data;
}

ByteView MessageCodec::encoded_packet_hash(ByteView packet_data) {
    SILKWORM_ASSERT(packet_data.size() >= sizeof(Packet));
    return packet_data.substr(0, sizeof(Packet{}.hash));
}

MessageEnvelope MessageCodec::decode(ByteView packet_data) {
    if (packet_data.size() < sizeof(Packet))
        throw std::runtime_error("MessageCodec: packet is too small");
    if (packet_data.size() > 1280)
        throw std::runtime_error("MessageCodec: packet is too big");
    auto packet = reinterpret_cast<const Packet*>(packet_data.data());

    if ((packet->type == 0) || (packet->type > static_cast<uint8_t>(PacketType::kMaxValue)))
        throw std::runtime_error("MessageCodec: invalid type");

    auto expected_hash = keccak256(packet_data.substr(offsetof(Packet, signature)));
    if (ByteView(packet->hash) != ByteView(expected_hash.bytes))
        throw std::runtime_error("MessageCodec: invalid hash");

    auto type_and_data_hash = keccak256(packet_data.substr(offsetof(Packet, type)));
    auto public_key = ecdsa_signature::verify_and_recover(
        ByteView(type_and_data_hash.bytes),
        ByteView(packet->signature));

    Message message{
        packet->type,
        Bytes(packet_data.substr(offsetof(Packet, data))),
    };

    return MessageEnvelope{
        std::move(message),
        std::move(public_key),
        Bytes(packet->hash, sizeof(packet->hash)),
    };
}

}  // namespace silkworm::sentry::discovery::disc_v4
