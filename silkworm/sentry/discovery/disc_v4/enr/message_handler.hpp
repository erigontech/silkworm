// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/udp.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>

#include "enr_request_message.hpp"
#include "enr_response_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::enr {

struct MessageHandler {
    virtual ~MessageHandler() = default;
    virtual Task<void> on_enr_request(
        EnrRequestMessage message,
        EccPublicKey sender_public_key,
        boost::asio::ip::udp::endpoint sender_endpoint,
        Bytes packet_hash) = 0;
    virtual Task<void> on_enr_response(EnrResponseMessage message) = 0;
};

}  // namespace silkworm::sentry::discovery::disc_v4::enr
