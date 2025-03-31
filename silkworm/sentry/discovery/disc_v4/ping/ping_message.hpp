// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>

#include <boost/asio/ip/udp.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/discovery/common/node_address.hpp>

namespace silkworm::sentry::discovery::disc_v4::ping {

struct PingMessage {
    boost::asio::ip::udp::endpoint sender_endpoint;
    uint16_t sender_port_rlpx{};
    boost::asio::ip::udp::endpoint recipient_endpoint;
    std::chrono::time_point<std::chrono::system_clock> expiration;
    std::optional<uint64_t> enr_seq_num;

    Bytes rlp_encode() const;
    static PingMessage rlp_decode(ByteView data);

    NodeAddress sender_node_address() const { return {sender_endpoint, sender_port_rlpx}; };

    static const uint8_t kId;
};

}  // namespace silkworm::sentry::discovery::disc_v4::ping
