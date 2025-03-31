// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/udp.hpp>

#include "ping_message.hpp"
#include "pong_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::ping {

struct MessageSender {
    virtual ~MessageSender() = default;
    virtual Task<void> send_ping(ping::PingMessage message, boost::asio::ip::udp::endpoint recipient) = 0;
    virtual Task<void> send_pong(ping::PongMessage message, boost::asio::ip::udp::endpoint recipient) = 0;
};

}  // namespace silkworm::sentry::discovery::disc_v4::ping
