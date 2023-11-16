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
#include <utility>

#include "task.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/cancellation_signal.hpp>

#include <silkworm/infra/concurrency/channel.hpp>

namespace silkworm::concurrency {

/**
 * TaskGroup is a limited version of a dynamic parallel_group (which asio lacks).
 *
 * The parallel_group (and awaitable_wait_for_all/awaitable_wait_for_one that are built on top of it)
 * supports "structured concurrency" approach for a fixed set of tasks.
 * If the number of tasks is not fixed, the only asio option is to use co_spawn(asio::detached),
 * but this violates the "structured concurrency" principle.
 *
 * TaskGroup works similarly to co_spawn(asio::detached), but keeps track of the spawned tasks.
 * When cancellation starts, TaskGroup gracefully cancels the tasks.
 *
 * Example:
 *
 * \code
 *
 * TaskGroup task_group{executor, 10};
 *
 * Task<void> run_server() {
 *     co_await (accept_connections() && task_group.wait());
 * }
 *
 * Task<void> accept_connections() {
 *     auto connection = accept();
 *     if (num_clients < 10) {
 *         num_clients++;
 *         task_group.spawn(executor, handle_connection(std::move(connection)));
 *     }
 * }
 *
 * \endcode
 *
 * \see https://vorpus.org/blog/notes-on-structured-concurrency-or-go-statement-considered-harmful/
 */
class TaskGroup {
  public:
    TaskGroup(const boost::asio::any_io_executor& executor, std::size_t max_tasks)
        : completions_(executor, max_tasks),
          exceptions_(executor, 1) {}

    TaskGroup(const TaskGroup&) = delete;
    TaskGroup& operator=(const TaskGroup&) = delete;

    class SpawnAfterCloseError : public std::runtime_error {
      public:
        SpawnAfterCloseError() : std::runtime_error("TaskGroup can't spawn after it was closed") {}
    };

    //! Similar to co_spawn, but also adds the task to this group until it completes.
    void spawn(const boost::asio::any_io_executor& executor, Task<void> task);

    //! Waits until a cancellation signal. then cancels all pending tasks, and waits for them to complete.
    Task<void> wait();

  private:
    void close();
    void on_complete(std::size_t task_id, const std::exception_ptr& ex_ptr);
    bool is_completed();

    std::mutex mutex_;
    bool is_closed_{false};
    std::size_t last_task_id_{0};
    std::map<std::size_t, boost::asio::cancellation_signal> tasks_;
    concurrency::Channel<std::pair<std::size_t, std::exception_ptr>> completions_;
    concurrency::Channel<std::exception_ptr> exceptions_;
};

}  // namespace silkworm::concurrency
