/*
   Copyright 2023 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

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
        return co_spawn(io_context_, std::move(task), boost::asio::use_future);
    }

    //! Poll until the spawned future completes
    template <typename TResult>
    void poll_context_until_future_is_ready(std::future<TResult>& future) {
        using namespace std::chrono_literals;
        restart_context();
        while (future.wait_for(0s) != std::future_status::ready) {
            poll_context_once();
        }
    }

    boost::asio::io_context& context() { return io_context_; }
    boost::asio::any_io_executor executor() { return io_context_.get_executor(); }

  protected:
    virtual void restart_context() { io_context_.restart(); }
    virtual void poll_context_once() { io_context_.poll_one(); }

    boost::asio::io_context io_context_;
};

}  // namespace silkworm::test_util
