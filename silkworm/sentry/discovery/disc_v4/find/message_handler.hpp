// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/sentry/common/ecc_public_key.hpp>

#include "find_node_message.hpp"
#include "neighbors_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::find {

struct MessageHandler {
    virtual ~MessageHandler() = default;
    virtual Task<void> on_find_node(FindNodeMessage message, EccPublicKey sender_public_key, boost::asio::ip::udp::endpoint sender_endpoint) = 0;
    virtual Task<void> on_neighbors(NeighborsMessage message, EccPublicKey sender_public_key) = 0;
};

}  // namespace silkworm::sentry::discovery::disc_v4::find
