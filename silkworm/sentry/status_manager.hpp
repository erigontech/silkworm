// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/sentry/common/atomic_value.hpp>

#include "eth/status_data.hpp"

namespace silkworm::sentry {

class StatusManager {
  public:
    explicit StatusManager(const boost::asio::any_io_executor& executor)
        : status_channel_(executor),
          status_(eth::StatusData{}) {}

    Task<void> wait_for_status();

    Task<void> run();

    concurrency::Channel<eth::StatusData>& status_channel() {
        return status_channel_;
    }

    std::function<eth::StatusData()> status_provider() {
        return status_.getter();
    }

  private:
    concurrency::Channel<eth::StatusData> status_channel_;
    AtomicValue<eth::StatusData> status_;
};

}  // namespace silkworm::sentry
