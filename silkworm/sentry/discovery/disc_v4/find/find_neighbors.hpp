// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/udp.hpp>
#include <boost/signals2.hpp>

#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/discovery/node_db/node_db.hpp>

#include "message_sender.hpp"
#include "neighbors_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::find {

Task<size_t> find_neighbors(
    EccPublicKey node_id,
    EccPublicKey local_node_id,
    MessageSender& message_sender,
    boost::signals2::signal<void(NeighborsMessage, EccPublicKey)>& on_neighbors_signal,
    node_db::NodeDb& db);

}  // namespace silkworm::sentry::discovery::disc_v4::find
