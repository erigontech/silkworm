// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/udp.hpp>

#include "enr_request_message.hpp"
#include "enr_response_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::enr {

struct MessageSender {
    virtual ~MessageSender() = default;
    virtual Task<void> send_enr_request(EnrRequestMessage message, boost::asio::ip::udp::endpoint recipient) = 0;
    virtual Task<void> send_enr_response(EnrResponseMessage message, boost::asio::ip::udp::endpoint recipient) = 0;
};

}  // namespace silkworm::sentry::discovery::disc_v4::enr
