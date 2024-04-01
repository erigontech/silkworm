/*
   Copyright 2024 The Silkworm Authors

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
#include <type_traits>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/compose.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace silkworm::rpc {

template <typename Executor, typename F, typename... Args>
// NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward) because of https://github.com/llvm/llvm-project/issues/68105
Task<std::invoke_result_t<F, Args...>> async_task(Executor runner, F&& fn, Args&&... args) {
    auto this_executor = co_await ThisTask::executor;
    co_return co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(std::exception_ptr, std::invoke_result_t<F, Args...>)>(
        [&this_executor, &runner, fn = std::forward<F>(fn), ...args = std::forward<Args>(args)](auto& self) {
            boost::asio::post(runner, [&, self = std::move(self)]() mutable {
                try {
                    auto result = std::invoke(fn, args...);
                    boost::asio::post(this_executor, [result = std::move(result), self = std::move(self)]() mutable {
                        if constexpr (std::is_void_v<std::invoke_result_t<F, Args...>>)
                            self.complete({});
                        else
                            self.complete({}, result);
                    });
                } catch (...) {
                    std::exception_ptr eptr = std::current_exception();
                    boost::asio::post(this_executor, [eptr, self = std::move(self)]() mutable {
                        if constexpr (std::is_void_v<std::invoke_result_t<F, Args...>>)
                            self.complete(eptr);
                        else
                            self.complete(eptr, {});
                    });
                }
            });
        },
        boost::asio::use_awaitable);
}

template <typename Executor, typename F, typename... Args>
requires std::is_void_v<std::invoke_result_t<F, Args...>>
// NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward) because of https://github.com/llvm/llvm-project/issues/68105
Task<void> async_task(Executor runner, F&& fn, Args&&... args) {
    auto this_executor = co_await ThisTask::executor;
    co_return co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(std::exception_ptr)>(
        [&this_executor, &runner, fn = std::forward<F>(fn), ...args = std::forward<Args>(args)](auto& self) {
            boost::asio::post(runner, [&, self = std::move(self)]() mutable {
                try {
                    std::invoke(fn, args...);
                    boost::asio::post(this_executor, [self = std::move(self)]() mutable {
                        self.complete({});
                    });
                } catch (...) {
                    std::exception_ptr eptr = std::current_exception();
                    boost::asio::post(this_executor, [eptr, self = std::move(self)]() mutable {
                        self.complete(eptr);
                    });
                }
            });
        },
        boost::asio::use_awaitable);
}

}  // namespace silkworm::rpc
