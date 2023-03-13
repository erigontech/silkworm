/*
   Copyright 2022 The Silkworm Authors

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

#include <exception>
#include <map>
#include <mutex>
#include <stdexcept>

#include <silkworm/node/concurrency/coroutine.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/io_context.hpp>

#include <silkworm/node/concurrency/channel.hpp>

namespace silkworm::sentry::common {

class TaskGroup {
  public:
    TaskGroup(boost::asio::any_io_executor&& executor, std::size_t max_tasks)
        : completions_(executor, max_tasks) {}
    TaskGroup(boost::asio::any_io_executor& executor, std::size_t max_tasks)
        : completions_(executor, max_tasks) {}
    TaskGroup(boost::asio::io_context& io_context, std::size_t max_tasks)
        : completions_(io_context, max_tasks) {}

    TaskGroup(const TaskGroup&) = delete;
    TaskGroup& operator=(const TaskGroup&) = delete;

    class SpawnAfterCloseError : public std::runtime_error {
      public:
        SpawnAfterCloseError() : std::runtime_error("TaskGroup can't spawn after it was closed") {}
    };

    void spawn(boost::asio::any_io_executor&& executor, boost::asio::awaitable<void> task);

    void spawn(boost::asio::any_io_executor& executor, boost::asio::awaitable<void> task) {
        spawn(boost::asio::any_io_executor{executor}, std::move(task));
    }

    void spawn(boost::asio::io_context& io_context, boost::asio::awaitable<void> task) {
        spawn(boost::asio::any_io_executor{io_context.get_executor()}, std::move(task));
    }

    boost::asio::awaitable<void> wait();

  private:
    void close();
    void on_complete(std::size_t task_id, const std::exception_ptr& ex_ptr);
    bool is_completed();

    std::mutex mutex_;
    bool is_closed_{false};
    std::size_t last_task_id_{0};
    std::map<std::size_t, boost::asio::cancellation_signal> tasks_;
    concurrency::Channel<std::size_t> completions_;
};

}  // namespace silkworm::sentry::common
