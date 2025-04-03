// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/udp.hpp>

#include <silkworm/sentry/discovery/node_db/node_db.hpp>

#include "find_node_message.hpp"
#include "message_sender.hpp"

namespace silkworm::sentry::discovery::disc_v4::find {

struct FindNodeHandler {
    static Task<void> handle(
        FindNodeMessage message,
        EccPublicKey sender_public_key,
        boost::asio::ip::udp::endpoint sender_endpoint,
        MessageSender& sender,
        node_db::NodeDb& db);
};

}  // namespace silkworm::sentry::discovery::disc_v4::find
