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

#include <utility>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/detail/type_traits.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>

#include <silkworm/infra/concurrency/context_pool.hpp>

namespace silkworm::concurrency {

template <typename Executor>
concept AsioExecutor = boost::asio::is_executor<Executor>::value || boost::asio::execution::is_executor<Executor>::value;

template <typename ExecutionContext>
concept AsioExecutionContext = std::is_convertible_v<ExecutionContext&, boost::asio::execution_context&>;

template <AsioExecutor Executor, typename F>
auto spawn_task(const Executor& ex, F&& f) {
    return boost::asio::co_spawn(ex, std::forward<F>(f), boost::asio::use_awaitable);
}

template <AsioExecutionContext ExecutionContext, typename F>
auto spawn_task(ExecutionContext& ctx, F&& f) {
    return boost::asio::co_spawn(ctx, std::forward<F>(f), boost::asio::use_awaitable);
}

template <AsioExecutor Executor, typename F>
auto spawn_future(const Executor& ex, F&& f) {
    return boost::asio::co_spawn(ex, std::forward<F>(f), boost::asio::use_future);
}

template <AsioExecutionContext ExecutionContext, typename F>
auto spawn_future(ExecutionContext& ctx, F&& f) {
    return boost::asio::co_spawn(ctx, std::forward<F>(f), boost::asio::use_future);
}

template <AsioExecutor Executor, typename F>
auto spawn_future_and_wait(const Executor& ex, F&& f) {
    return spawn_future(ex, std::forward<F>(f)).get();
}

template <AsioExecutionContext ExecutionContext, typename F>
auto spawn_future_and_wait(ExecutionContext& ctx, F&& f) {
    return spawn_future(ctx, std::forward<F>(f)).get();
}

}  // namespace silkworm::concurrency
