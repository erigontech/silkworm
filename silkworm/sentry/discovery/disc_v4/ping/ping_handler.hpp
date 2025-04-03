// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/udp.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/discovery/node_db/node_db.hpp>

#include "message_sender.hpp"
#include "ping_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::ping {

struct PingHandler {
    static Task<bool> handle(
        PingMessage message,
        EccPublicKey sender_public_key,
        boost::asio::ip::udp::endpoint sender_endpoint,
        Bytes ping_packet_hash,
        EccPublicKey local_node_id,
        uint64_t local_enr_seq_num,
        MessageSender& sender,
        node_db::NodeDb& db);
};

}  // namespace silkworm::sentry::discovery::disc_v4::ping
