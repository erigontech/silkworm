// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/rlp/decode.hpp>

namespace silkworm::sentry::discovery {

struct NodeAddress {
    boost::asio::ip::udp::endpoint endpoint;
    uint16_t port_rlpx{};

    NodeAddress() = default;

    NodeAddress(boost::asio::ip::udp::endpoint endpoint1, uint16_t port_rlpx1)
        : endpoint(std::move(endpoint1)),
          port_rlpx(port_rlpx1) {}

    NodeAddress(const boost::asio::ip::address& ip, uint16_t port_disc, uint16_t port_rlpx1)
        : endpoint(ip, port_disc),
          port_rlpx(port_rlpx1) {}
};

//! RLP length
size_t length(const NodeAddress&);
//! RLP encode
void encode(Bytes& to, const NodeAddress&);
DecodingResult decode(ByteView& from, NodeAddress& to, rlp::Leftover mode) noexcept;

Bytes ip_address_to_bytes(const boost::asio::ip::address& ip);
std::optional<boost::asio::ip::address> ip_address_from_bytes(ByteView ip_bytes) noexcept;

}  // namespace silkworm::sentry::discovery
