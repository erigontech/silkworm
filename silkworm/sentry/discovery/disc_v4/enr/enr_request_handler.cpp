// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "enr_request_handler.hpp"

#include <chrono>

#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/message_expiration.hpp>
#include <silkworm/sentry/discovery/disc_v4/ping/ping_check.hpp>

#include "enr_response_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::enr {

Task<void> EnrRequestHandler::handle(
    EnrRequestMessage message,
    EccPublicKey sender_public_key,
    boost::asio::ip::udp::endpoint sender_endpoint,
    Bytes packet_hash,
    discovery::enr::EnrRecord local_node_record,
    MessageSender& sender,
    node_db::NodeDb& db) {
    if (is_expired_message_expiration(message.expiration)) {
        co_return;
    }

    // check that the sender has a valid pong
    auto last_pong_time = co_await db.find_last_pong_time(sender_public_key);
    auto now = std::chrono::system_clock::system_clock::now();
    if (!last_pong_time || (*last_pong_time < ping::min_valid_pong_time(now))) {
        co_return;
    }

    auto& recipient = sender_endpoint;
    EnrResponseMessage response{
        std::move(packet_hash),
        std::move(local_node_record),
    };

    try {
        co_await sender.send_enr_response(std::move(response), recipient);
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled)
            throw;
        SILK_WARN_M("disc_v4")
            << "EnrRequestHandler::handle failed to reply"
            << " to " << recipient
            << " due to exception: " << ex.what();
    }
}

}  // namespace silkworm::sentry::discovery::disc_v4::enr
