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

using namespace boost::asio;  // TODO(remove)

template <typename Executor, typename F>
auto spawn_and_async_wait(const Executor& ex, F&& f,
                          typename boost::asio::constraint<
                              boost::asio::is_executor<Executor>::value || boost::asio::execution::is_executor<Executor>::value>::type = 0) {
    return boost::asio::co_spawn(ex, std::forward<F>(f), boost::asio::use_awaitable);
}

template <typename ExecutionContext, typename F>
auto spawn_and_async_wait(ExecutionContext& ctx, F&& f,
                          typename boost::asio::constraint<std::is_convertible_v<ExecutionContext&, boost::asio::execution_context&>>::type = 0) {
    return boost::asio::co_spawn(ctx, std::forward<F>(f), boost::asio::use_awaitable);
}

template <typename Executor, typename F>
auto spawn(const Executor& ex, F&& f,
           typename boost::asio::constraint<
               boost::asio::is_executor<Executor>::value || boost::asio::execution::is_executor<Executor>::value>::type = 0) {
    return boost::asio::co_spawn(ex, std::forward<F>(f), boost::asio::use_future);
}

template <typename ExecutionContext, typename F>
auto spawn(ExecutionContext& ctx, F&& f,
           typename boost::asio::constraint<std::is_convertible_v<ExecutionContext&, boost::asio::execution_context&>>::type = 0) {
    return boost::asio::co_spawn(ctx, std::forward<F>(f), boost::asio::use_future);
}

template <typename Executor, typename F>
auto spawn_and_wait(const Executor& ex, F&& f,
                    typename boost::asio::constraint<
                        boost::asio::is_executor<Executor>::value || boost::asio::execution::is_executor<Executor>::value>::type = 0) {
    return spawn(ex, std::forward<F>(f)).get();
}

template <typename ExecutionContext, typename F>
auto spawn_and_wait(ExecutionContext& ctx, F&& f,
                    typename boost::asio::constraint<std::is_convertible_v<ExecutionContext&, boost::asio::execution_context&>>::type = 0) {
    return spawn(ctx, std::forward<F>(f)).get();
}

}  // namespace silkworm::concurrency
