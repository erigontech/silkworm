// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ping_handler.hpp"

#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/message_expiration.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/node_distance.hpp>

#include "pong_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::ping {

Task<bool> PingHandler::handle(
    PingMessage message,
    EccPublicKey sender_public_key,
    boost::asio::ip::udp::endpoint sender_endpoint,
    Bytes ping_packet_hash,
    EccPublicKey local_node_id,
    uint64_t local_enr_seq_num,
    MessageSender& sender,
    node_db::NodeDb& db) {
    if (is_expired_message_expiration(message.expiration)) {
        co_return false;
    }

    auto& recipient = sender_endpoint;
    PongMessage pong{
        recipient,
        ping_packet_hash,
        make_message_expiration(),
        local_enr_seq_num,
    };

    try {
        co_await sender.send_pong(std::move(pong), recipient);
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled)
            throw;
        SILK_WARN_M("disc_v4")
            << "PingHandler::handle failed to reply"
            << " to " << recipient
            << " due to exception: " << ex.what();
        co_return false;
    }

    // in misconfigured systems we might receive a ping from "ourselves"
    if (sender_public_key == local_node_id) {
        co_return false;
    }

    // save a ping sender node as if it was discovered by find_neighbors()
    bool is_inserted = co_await db.upsert_node_address(sender_public_key, message.sender_node_address());
    if (is_inserted) {
        co_await db.update_distance(sender_public_key, node_distance(sender_public_key, local_node_id));
    }
    co_return is_inserted;
}

}  // namespace silkworm::sentry::discovery::disc_v4::ping
