// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "neighbors_message.hpp"

#include <stdexcept>
#include <vector>

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/unix_timestamp.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/packet_type.hpp>

namespace silkworm::sentry::discovery::disc_v4::find {

const uint8_t NeighborsMessage::kId = static_cast<uint8_t>(PacketType::kNeighbors);

struct NeighborsNodeInfo {
    NodeAddress address;
    EccPublicKey public_key{Bytes{}};
};

//! RLP length of NeighborsNodeInfo
size_t length(const NeighborsNodeInfo& info) {
    auto& address = info.address;
    return rlp::length(ip_address_to_bytes(address.endpoint.address()), address.endpoint.port(), address.port_rlpx, info.public_key.serialized());
}

//! RLP encode NeighborsNodeInfo
void encode(Bytes& to, const NeighborsNodeInfo& info) {
    auto& address = info.address;
    rlp::encode(to, ip_address_to_bytes(address.endpoint.address()), address.endpoint.port(), address.port_rlpx, info.public_key.serialized());
}

//! RLP decode NeighborsNodeInfo
DecodingResult decode(ByteView& from, NeighborsNodeInfo& to, rlp::Leftover mode) noexcept {
    Bytes ip_bytes;
    uint16_t port{0};
    Bytes public_key_data;
    auto result = rlp::decode(from, mode, ip_bytes, port, to.address.port_rlpx, public_key_data);
    if (!result) {
        return result;
    }

    auto ip = ip_address_from_bytes(ip_bytes);
    if (!ip) {
        return tl::unexpected{DecodingError::kUnexpectedString};
    }

    to.address.endpoint = boost::asio::ip::udp::endpoint(*ip, port);

    try {
        to.public_key = EccPublicKey::deserialize(public_key_data);
    } catch (const std::runtime_error&) {
        return tl::unexpected{DecodingError::kUnexpectedString};
    }

    return result;
}

Bytes NeighborsMessage::rlp_encode() const {
    std::vector<NeighborsNodeInfo> node_infos;
    node_infos.reserve(node_addresses.size());
    for (const auto& [public_key, address] : node_addresses) {
        node_infos.push_back({address, public_key});
    }

    auto expiration_ts = unix_timestamp_from_time_point(expiration);

    Bytes data;
    rlp::encode(data, node_infos, expiration_ts);
    return data;
}

NeighborsMessage NeighborsMessage::rlp_decode(ByteView data) {
    std::vector<NeighborsNodeInfo> node_infos;
    uint64_t expiration_ts{0};

    auto result = rlp::decode(
        data,
        rlp::Leftover::kAllow,
        node_infos,
        expiration_ts);
    if (!result && (result.error() != DecodingError::kUnexpectedListElements)) {
        throw DecodingException(result.error(), "Failed to decode NeighborsMessage RLP");
    }

    std::map<EccPublicKey, NodeAddress> node_addresses;
    for (auto& info : node_infos) {
        node_addresses[info.public_key] = info.address;
    }

    return NeighborsMessage{
        std::move(node_addresses),
        time_point_from_unix_timestamp(expiration_ts),
    };
}

}  // namespace silkworm::sentry::discovery::disc_v4::find
