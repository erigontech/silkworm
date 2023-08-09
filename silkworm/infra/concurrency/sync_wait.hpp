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

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>

namespace silkworm {

/**
 * Do a synchronous wait of a coroutine on the specified io_context
 *
 * sync_wait:
 * - schedules a coroutine for execution in the specified io_context
 * - blocks the calling thread until the coroutine completes
 * - returns the result of the coroutine
 *
 * Rationale: doing an asynchronous wait of a coroutine is easy:
 *    auto result = co_await task();
 * Doing a synchronous wait of a coroutine is more verbose:
 *    auto result = co_spawn(io_context, task(), use_future).get();
 * also this exposes implementation details.
 * Using sync_wait the call becomes:
 *   auto result = sync_wait(io_context, task());
 * Or, if the current object has an io_context:
 *   auto result = sync_wait(in(this), task());
 *
 */
template <typename T>
T sync_wait(boost::asio::io_context& io_context, const Task<T>& task) {
    auto future_result = boost::asio::co_spawn(io_context, task, boost::asio::use_future);
    return future_result.get();
}

template <typename T>
T sync_wait(boost::asio::io_context& io_context, Task<T>&& task) {
    auto future_result = boost::asio::co_spawn(io_context, std::move(task), boost::asio::use_future);
    return future_result.get();
}

/**
 * Simplify the call to sync_wait
 *
 * When the desired io_context is not immediately available in the scope of the caller,
 * but is owned by some object, this function can be used to retrieve it and simplify
 * the call to sync_wait
 *
 * For example, provided that some class Engine has an io_context:
 *    sync_wait(in(engine), engine.do_work());
 * or provided that the current object has an io_context:
 *    sync_wait(in(this), engine.do_work());
 */

template <typename C>
boost::asio::io_context& in(C& context) {
    return context.get_executor();
}

}  // namespace silkworm