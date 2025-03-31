// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/udp.hpp>

#include "find_node_message.hpp"
#include "neighbors_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::find {

struct MessageSender {
    virtual ~MessageSender() = default;
    virtual Task<void> send_find_node(find::FindNodeMessage message, boost::asio::ip::udp::endpoint recipient) = 0;
    virtual Task<void> send_neighbors(find::NeighborsMessage message, boost::asio::ip::udp::endpoint recipient) = 0;
};

}  // namespace silkworm::sentry::discovery::disc_v4::find
