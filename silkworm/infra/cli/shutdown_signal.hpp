// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/signal_set.hpp>

namespace silkworm::cmd::common {

class ShutdownSignal {
  public:
    explicit ShutdownSignal(const boost::asio::any_io_executor& executor)
        : signals_(executor, SIGINT, SIGTERM) {}

    void cancel();

    using SignalNumber = int;

    void on_signal(std::function<void(SignalNumber)> callback);

    Task<SignalNumber> wait_me();
    static Task<SignalNumber> wait();

  private:
    boost::asio::signal_set signals_;
};

}  // namespace silkworm::cmd::common
