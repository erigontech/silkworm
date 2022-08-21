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

//
// Copyright (c) 2003-2021 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <variant>

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/completion_condition.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/cancellation_condition.hpp>
#include <boost/asio/experimental/deferred.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/multiple_exceptions.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace silkworm::sentry::common::awaitable_wait_for_one {

using boost::asio::experimental::wait_for_one;

template <typename T, typename Executor = boost::asio::any_io_executor>
using awaitable = boost::asio::awaitable<T, Executor>;

template <typename Executor = boost::asio::any_io_executor>
using use_awaitable_t = boost::asio::use_awaitable_t<Executor>;

using boost::asio::experimental::deferred;

namespace this_coro {
    using boost::asio::this_coro::executor;
}

namespace detail {
    using boost::asio::experimental::awaitable_operators::detail::awaitable_unwrap;
    using boost::asio::experimental::awaitable_operators::detail::awaitable_wrap;
    using boost::asio::experimental::awaitable_operators::detail::widen_variant;
}  // namespace detail

using boost::asio::multiple_exceptions;

/// Wait for one operation to succeed.
/**
 * If one operations succeeds, the other is cancelled as the OR-condition is
 * already satisfied.
 */
template <typename Executor>
awaitable<std::variant<std::monostate, std::monostate>, Executor> operator||(awaitable<void, Executor> t,
                                                                             awaitable<void, Executor> u) {
    auto ex = co_await this_coro::executor;

    auto [order, ex0, ex1] =
        co_await make_parallel_group(co_spawn(ex, std::move(t), deferred), co_spawn(ex, std::move(u), deferred))
            .async_wait(wait_for_one(), use_awaitable_t<Executor>{});

    if (order[0] == 0) {
        if (!ex0) co_return std::variant<std::monostate, std::monostate>{std::in_place_index<0>};
        std::rethrow_exception(ex0);
    } else {
        if (!ex1) co_return std::variant<std::monostate, std::monostate>{std::in_place_index<1>};
        std::rethrow_exception(ex1);
    }
}

/// Wait for one operation to succeed.
/**
 * If one operations succeeds, the other is cancelled as the OR-condition is
 * already satisfied.
 */
template <typename U, typename Executor>
awaitable<std::variant<std::monostate, U>, Executor> operator||(awaitable<void, Executor> t, awaitable<U, Executor> u) {
    auto ex = co_await this_coro::executor;

    auto [order, ex0, ex1, r1] =
        co_await make_parallel_group(co_spawn(ex, std::move(t), deferred),
                                     co_spawn(ex, detail::awaitable_wrap(std::move(u)), deferred))
            .async_wait(wait_for_one(), use_awaitable_t<Executor>{});

    if (order[0] == 0) {
        if (!ex0) co_return std::variant<std::monostate, U>{std::in_place_index<0>};
        std::rethrow_exception(ex0);
    } else {
        if (!ex1)
            co_return std::variant<std::monostate, U>{std::in_place_index<1>,
                                                      std::move(detail::awaitable_unwrap<U>(r1))};
        std::rethrow_exception(ex1);
    }
}

/// Wait for one operation to succeed.
/**
 * If one operations succeeds, the other is cancelled as the OR-condition is
 * already satisfied.
 */
template <typename T, typename Executor>
awaitable<std::variant<T, std::monostate>, Executor> operator||(awaitable<T, Executor> t, awaitable<void, Executor> u) {
    auto ex = co_await this_coro::executor;

    auto [order, ex0, r0, ex1] =
        co_await make_parallel_group(co_spawn(ex, detail::awaitable_wrap(std::move(t)), deferred),
                                     co_spawn(ex, std::move(u), deferred))
            .async_wait(wait_for_one(), use_awaitable_t<Executor>{});

    if (order[0] == 0) {
        if (!ex0)
            co_return std::variant<T, std::monostate>{std::in_place_index<0>,
                                                      std::move(detail::awaitable_unwrap<T>(r0))};
        std::rethrow_exception(ex0);
    } else {
        if (!ex1) co_return std::variant<T, std::monostate>{std::in_place_index<1>};
        std::rethrow_exception(ex1);
    }
}

/// Wait for one operation to succeed.
/**
 * If one operations succeeds, the other is cancelled as the OR-condition is
 * already satisfied.
 */
template <typename T, typename U, typename Executor>
awaitable<std::variant<T, U>, Executor> operator||(awaitable<T, Executor> t, awaitable<U, Executor> u) {
    auto ex = co_await this_coro::executor;

    auto [order, ex0, r0, ex1, r1] =
        co_await make_parallel_group(co_spawn(ex, detail::awaitable_wrap(std::move(t)), deferred),
                                     co_spawn(ex, detail::awaitable_wrap(std::move(u)), deferred))
            .async_wait(wait_for_one(), use_awaitable_t<Executor>{});

    if (order[0] == 0) {
        if (!ex0) co_return std::variant<T, U>{std::in_place_index<0>, std::move(detail::awaitable_unwrap<T>(r0))};
        std::rethrow_exception(ex0);
    } else {
        if (!ex1) co_return std::variant<T, U>{std::in_place_index<1>, std::move(detail::awaitable_unwrap<U>(r1))};
        std::rethrow_exception(ex1);
    }
}

/// Wait for one operation to succeed.
/**
 * If one operations succeeds, the other is cancelled as the OR-condition is
 * already satisfied.
 */
template <typename... T, typename Executor>
awaitable<std::variant<T..., std::monostate>, Executor> operator||(awaitable<std::variant<T...>, Executor> t,
                                                                   awaitable<void, Executor> u) {
    auto ex = co_await this_coro::executor;

    auto [order, ex0, r0, ex1] =
        co_await make_parallel_group(co_spawn(ex, detail::awaitable_wrap(std::move(t)), deferred),
                                     co_spawn(ex, std::move(u), deferred))
            .async_wait(wait_for_one(), use_awaitable_t<Executor>{});

    using widen = detail::widen_variant<T..., std::monostate>;
    if (order[0] == 0) {
        if (!ex0) co_return widen::template call<0>(detail::awaitable_unwrap<std::variant<T...>>(r0));
        std::rethrow_exception(ex0);
    } else {
        if (!ex1) co_return std::variant<T..., std::monostate>{std::in_place_index<sizeof...(T)>};
        std::rethrow_exception(ex1);
    }
}

/// Wait for one operation to succeed.
/**
 * If one operations succeeds, the other is cancelled as the OR-condition is
 * already satisfied.
 */
template <typename... T, typename U, typename Executor>
awaitable<std::variant<T..., U>, Executor> operator||(awaitable<std::variant<T...>, Executor> t,
                                                      awaitable<U, Executor> u) {
    auto ex = co_await this_coro::executor;

    auto [order, ex0, r0, ex1, r1] =
        co_await make_parallel_group(co_spawn(ex, detail::awaitable_wrap(std::move(t)), deferred),
                                     co_spawn(ex, detail::awaitable_wrap(std::move(u)), deferred))
            .async_wait(wait_for_one(), use_awaitable_t<Executor>{});

    using widen = detail::widen_variant<T..., U>;
    if (order[0] == 0) {
        if (!ex0) co_return widen::template call<0>(detail::awaitable_unwrap<std::variant<T...>>(r0));
        std::rethrow_exception(ex0);
    } else {
        if (!ex1)
            co_return std::variant<T..., U>{std::in_place_index<sizeof...(T)>,
                                            std::move(detail::awaitable_unwrap<U>(r1))};
        std::rethrow_exception(ex1);
    }
}

}  // namespace silkworm::sentry::common::awaitable_wait_for_one
