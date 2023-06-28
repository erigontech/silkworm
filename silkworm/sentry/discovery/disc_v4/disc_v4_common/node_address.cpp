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

#include "node_address.hpp"

#include <cstring>

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>

namespace silkworm::sentry::discovery::disc_v4::disc_v4_common {

Bytes ip_address_to_bytes(const boost::asio::ip::address& ip) {
    if (ip.is_v4()) {
        auto ip_bytes = ip.to_v4().to_bytes();
        return Bytes{reinterpret_cast<uint8_t*>(ip_bytes.data()), ip_bytes.size()};
    }
    if (ip.is_v6()) {
        auto ip_bytes = ip.to_v6().to_bytes();
        return Bytes{reinterpret_cast<uint8_t*>(ip_bytes.data()), ip_bytes.size()};
    }
    return {};
}

std::optional<boost::asio::ip::address> ip_address_from_bytes(ByteView ip_bytes) noexcept {
    if (ip_bytes.size() == sizeof(boost::asio::ip::address_v4::bytes_type)) {
        boost::asio::ip::address_v4::bytes_type ip_bytes_array;
        memcpy(ip_bytes_array.data(), ip_bytes.data(), ip_bytes.size());
        return {boost::asio::ip::address_v4{ip_bytes_array}};
    }
    if (ip_bytes.size() == sizeof(boost::asio::ip::address_v6::bytes_type)) {
        boost::asio::ip::address_v6::bytes_type ip_bytes_array;
        memcpy(ip_bytes_array.data(), ip_bytes.data(), ip_bytes.size());
        return {boost::asio::ip::address_v6{ip_bytes_array}};
    }
    return std::nullopt;
}

//! RLP length
size_t length(const NodeAddress& address) {
    return rlp::length(ip_address_to_bytes(address.endpoint.address()), address.endpoint.port(), address.port_rlpx);
}

//! RLP encode
void encode(Bytes& to, const NodeAddress& address) {
    rlp::encode(to, ip_address_to_bytes(address.endpoint.address()), address.endpoint.port(), address.port_rlpx);
}

//! RLP decode
DecodingResult decode(ByteView& from, NodeAddress& to, rlp::Leftover mode) noexcept {
    Bytes ip_bytes;
    uint16_t port;
    auto result = rlp::decode(from, mode, ip_bytes, port, to.port_rlpx);
    if (!result) {
        return result;
    }

    auto ip = ip_address_from_bytes(ip_bytes);
    if (!ip) {
        return tl::unexpected{DecodingError::kUnexpectedString};
    }

    to.endpoint = boost::asio::ip::udp::endpoint(*ip, port);
    return result;
}

}  // namespace silkworm::sentry::discovery::disc_v4::disc_v4_common
