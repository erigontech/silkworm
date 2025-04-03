// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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

//! Helper trait for any completion handler signature
template <typename R, typename F, typename... Args>
struct CompletionHandler {
    using type = void(std::exception_ptr, R);
};

//! Partial specialization for \code void return type
template <typename F, typename... Args>
struct CompletionHandler<void, F, Args...> {
    using type = void(std::exception_ptr);
};

//! Alias helper trait for the completion handler signature of any task
template <typename F, typename... Args>
using TaskCompletionHandler = typename CompletionHandler<std::invoke_result_t<F, Args...>, F, Args...>::type;

//! Asynchronous \code co_await-able task executing function \code fn with arguments \code args in \code runner executor
template <typename Executor, typename F, typename... Args>
// NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward) because of https://github.com/llvm/llvm-project/issues/68105
Task<std::invoke_result_t<F, Args...>> async_task(Executor runner, F&& fn, Args&&... args) {
    auto this_executor = co_await boost::asio::this_coro::executor;
    co_return co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), TaskCompletionHandler<F, Args...>>(
        [&this_executor, &runner, fn = std::forward<F>(fn), ... args = std::forward<Args>(args)](auto& self) mutable {
            boost::asio::post(runner, [&, fn = std::forward<decltype(fn)>(fn), ... args = std::forward<Args>(args), self = std::move(self)]() mutable {
                try {
                    if constexpr (std::is_void_v<std::invoke_result_t<F, Args...>>) {
                        std::invoke(fn, args...);
                        boost::asio::post(this_executor, [self = std::move(self)]() mutable {
                            self.complete({});
                        });
                    } else {
                        auto result = std::invoke(fn, args...);
                        boost::asio::post(this_executor, [result = std::move(result), self = std::move(self)]() mutable {
                            self.complete({}, result);
                        });
                    }
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

}  // namespace silkworm::rpc
