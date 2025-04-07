// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <optional>

#include <boost/asio/ip/udp.hpp>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::sentry::discovery::disc_v4::ping {

struct PongMessage {
    boost::asio::ip::udp::endpoint recipient_endpoint;
    Bytes ping_hash;
    std::chrono::time_point<std::chrono::system_clock> expiration;
    std::optional<uint64_t> enr_seq_num;

    Bytes rlp_encode() const;
    static PongMessage rlp_decode(ByteView data);

    static const uint8_t kId;
};

}  // namespace silkworm::sentry::discovery::disc_v4::ping
