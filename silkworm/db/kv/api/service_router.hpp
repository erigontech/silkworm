// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <silkworm/infra/concurrency/channel.hpp>

#include "endpoint/state_changes_call.hpp"

namespace silkworm::db::kv::api {

struct ServiceRouter {
    concurrency::Channel<StateChangesCall>& state_changes_calls_channel;
};

class StateChangeRunner {
  public:
    static Task<void> run(std::shared_ptr<StateChangeRunner> self);

    explicit StateChangeRunner(const boost::asio::any_io_executor& executor);

    template <typename T>
    using Channel = concurrency::Channel<T>;

    Channel<StateChangesCall>& state_changes_calls_channel() {
        return state_changes_calls_channel_;
    }

  private:
    Task<void> handle_calls();

    Channel<StateChangesCall> state_changes_calls_channel_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
};

}  // namespace silkworm::db::kv::api
