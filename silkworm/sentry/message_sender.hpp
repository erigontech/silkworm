// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/sentry/api/router/send_message_call.hpp>

#include "peer_manager.hpp"

namespace silkworm::sentry {

class MessageSender {
  public:
    explicit MessageSender(const boost::asio::any_io_executor& executor)
        : send_message_channel_(executor) {}

    concurrency::Channel<api::router::SendMessageCall>& send_message_channel() {
        return send_message_channel_;
    }

    Task<void> run(PeerManager& peer_manager);

  private:
    concurrency::Channel<api::router::SendMessageCall> send_message_channel_;
};

}  // namespace silkworm::sentry
