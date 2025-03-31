// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <future>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>

namespace silkworm::test_util {

/**
 * A helper to run Task-s on io_context in tests
 */
class TaskRunner {
  public:
    TaskRunner() = default;
    virtual ~TaskRunner() = default;

    //! Run task to completion
    template <typename TResult>
    TResult run(Task<TResult> task) {
        auto future = spawn_future(std::move(task));
        poll_context_until_future_is_ready(future);
        return future.get();
    }

    //! co_spawn with use_future
    template <typename TResult>
    std::future<TResult> spawn_future(Task<TResult> task) {
        return co_spawn(ioc_, std::move(task), boost::asio::use_future);
    }

    //! Poll until the spawned future completes
    template <typename TResult>
    void poll_context_until_future_is_ready(std::future<TResult>& future) {
        using namespace std::chrono_literals;
        restart_ioc();
        while (future.wait_for(0s) != std::future_status::ready) {
            poll_ioc_once();
        }
    }

    boost::asio::io_context& ioc() { return ioc_; }
    boost::asio::any_io_executor executor() { return ioc_.get_executor(); }

  protected:
    virtual void restart_ioc() { ioc_.restart(); }
    virtual void poll_ioc_once() { ioc_.poll_one(); }

    boost::asio::io_context ioc_;
};

}  // namespace silkworm::test_util
