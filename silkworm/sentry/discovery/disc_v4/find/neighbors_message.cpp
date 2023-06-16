/*
   Copyright 2023 The Silkworm Authors

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

#include "neighbors_message.hpp"

#include <stdexcept>
#include <vector>

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/sentry/discovery/disc_v4/disc_v4_common/unix_timestamp.hpp>

namespace silkworm::sentry::discovery::disc_v4::find {

using namespace disc_v4_common;

struct NeighborsNodeInfo {
    NodeAddress address;
    common::EccPublicKey public_key{Bytes{}};
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
    uint16_t port;
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
        to.public_key = common::EccPublicKey::deserialize(public_key_data);
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
    uint64_t expiration_ts;

    auto result = rlp::decode(
        data,
        rlp::Leftover::kAllow,
        node_infos,
        expiration_ts);
    if (!result && (result.error() != DecodingError::kUnexpectedListElements)) {
        throw DecodingException(result.error(), "Failed to decode NeighborsMessage RLP");
    }

    std::map<common::EccPublicKey, disc_v4_common::NodeAddress> node_addresses;
    for (auto& info : node_infos) {
        node_addresses[info.public_key] = info.address;
    }

    return NeighborsMessage{
        std::move(node_addresses),
        time_point_from_unix_timestamp(expiration_ts),
    };
}

}  // namespace silkworm::sentry::discovery::disc_v4::find
