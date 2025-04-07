// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <variant>

#include "task.hpp"

#include <boost/asio/any_io_executor.hpp>

#include "channel.hpp"

namespace silkworm::concurrency {

// A simplified condition variable similar to Rust Tokio Notify:
// https://docs.rs/tokio/1.25.0/tokio/sync/struct.Notify.html
// Only one waiter is supported.
class EventNotifier {
  public:
    explicit EventNotifier(const boost::asio::any_io_executor& executor) : channel_(executor, 1) {}

    Task<void> wait() {
        co_await channel_.receive();
    }

    void notify() {
        channel_.try_send({});
    }

  private:
    Channel<std::monostate> channel_;
};

}  // namespace silkworm::concurrency
