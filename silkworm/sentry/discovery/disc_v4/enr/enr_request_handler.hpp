// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/udp.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/discovery/enr/enr_record.hpp>
#include <silkworm/sentry/discovery/node_db/node_db.hpp>

#include "enr_request_message.hpp"
#include "message_sender.hpp"

namespace silkworm::sentry::discovery::disc_v4::enr {

struct EnrRequestHandler {
    static Task<void> handle(
        EnrRequestMessage message,
        EccPublicKey sender_public_key,
        boost::asio::ip::udp::endpoint sender_endpoint,
        Bytes packet_hash,
        discovery::enr::EnrRecord local_node_record,
        MessageSender& sender,
        node_db::NodeDb& db);
};

}  // namespace silkworm::sentry::discovery::disc_v4::enr
