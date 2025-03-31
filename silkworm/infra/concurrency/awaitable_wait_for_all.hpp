// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

//
// Copyright (c) 2003-2021 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <variant>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "parallel_group_utils.hpp"
#include "spawn.hpp"

namespace silkworm::concurrency::awaitable_wait_for_all {

using boost::asio::experimental::wait_for_one_error;

template <typename T, typename Executor = boost::asio::any_io_executor>
using awaitable = boost::asio::awaitable<T, Executor>;

template <typename Executor = boost::asio::any_io_executor>
using use_awaitable_t = boost::asio::use_awaitable_t<Executor>;

using boost::asio::deferred;
using boost::asio::experimental::make_parallel_group;

namespace this_coro {
    using boost::asio::this_coro::executor;
}

namespace detail {
    using boost::asio::experimental::awaitable_operators::detail::awaitable_unwrap;
    using boost::asio::experimental::awaitable_operators::detail::awaitable_wrap;
    using boost::asio::experimental::awaitable_operators::detail::widen_variant;
}  // namespace detail

//! Wait for both operations to succeed.
/**
 * If one operations fails, the other is cancelled as the AND-condition can no
 * longer be satisfied.
 */
template <typename Executor>
awaitable<void, Executor> operator&&(
    awaitable<void, Executor> t, awaitable<void, Executor> u) {
    auto ex = co_await this_coro::executor;

    auto [order, ex0, ex1] =
        co_await make_parallel_group(
            co_spawn(ex, std::move(t), deferred),
            co_spawn(ex, std::move(u), deferred))
            .async_wait(
                wait_for_one_error(),
                use_awaitable_t<Executor>{});

    rethrow_first_exception_if_any({ex0, ex1}, order);
    co_return;
}

//! Wait for both operations to succeed.
/**
 * If one operations fails, the other is cancelled as the AND-condition can no
 * longer be satisfied.
 */
template <typename U, typename Executor>
awaitable<U, Executor> operator&&(
    awaitable<void, Executor> t, awaitable<U, Executor> u) {
    auto ex = co_await this_coro::executor;

    auto [order, ex0, ex1, r1] =
        co_await make_parallel_group(
            co_spawn(ex, std::move(t), deferred),
            co_spawn(ex, detail::awaitable_wrap(std::move(u)), deferred))
            .async_wait(
                wait_for_one_error(),
                use_awaitable_t<Executor>{});

    rethrow_first_exception_if_any({ex0, ex1}, order);
    co_return std::move(detail::awaitable_unwrap<U>(r1));
}

//! Wait for both operations to succeed.
/**
 * If one operations fails, the other is cancelled as the AND-condition can no
 * longer be satisfied.
 */
template <typename T, typename Executor>
awaitable<T, Executor> operator&&(
    awaitable<T, Executor> t, awaitable<void, Executor> u) {
    auto ex = co_await this_coro::executor;

    auto [order, ex0, r0, ex1] =
        co_await make_parallel_group(
            co_spawn(ex, detail::awaitable_wrap(std::move(t)), deferred),
            co_spawn(ex, std::move(u), deferred))
            .async_wait(
                wait_for_one_error(),
                use_awaitable_t<Executor>{});

    rethrow_first_exception_if_any({ex0, ex1}, order);
    co_return std::move(detail::awaitable_unwrap<T>(r0));
}

//! Wait for both operations to succeed.
/**
 * If one operations fails, the other is cancelled as the AND-condition can no
 * longer be satisfied.
 */
template <typename T, typename U, typename Executor>
awaitable<std::tuple<T, U>, Executor> operator&&(
    awaitable<T, Executor> t, awaitable<U, Executor> u) {
    auto ex = co_await this_coro::executor;

    auto [order, ex0, r0, ex1, r1] =
        co_await make_parallel_group(
            co_spawn(ex, detail::awaitable_wrap(std::move(t)), deferred),
            co_spawn(ex, detail::awaitable_wrap(std::move(u)), deferred))
            .async_wait(
                wait_for_one_error(),
                use_awaitable_t<Executor>{});

    rethrow_first_exception_if_any({ex0, ex1}, order);
    co_return std::make_tuple(
        std::move(detail::awaitable_unwrap<T>(r0)),
        std::move(detail::awaitable_unwrap<U>(r1)));
}

//! Wait for both operations to succeed.
/**
 * If one operations fails, the other is cancelled as the AND-condition can no
 * longer be satisfied.
 */
template <typename... T, typename Executor>
awaitable<std::tuple<T..., std::monostate>, Executor> operator&&(
    awaitable<std::tuple<T...>, Executor> t, awaitable<void, Executor> u) {
    auto ex = co_await this_coro::executor;

    auto [order, ex0, r0, ex1, r1] =
        co_await make_parallel_group(
            co_spawn(ex, detail::awaitable_wrap(std::move(t)), deferred),
            co_spawn(ex, std::move(u), deferred))
            .async_wait(
                wait_for_one_error(),
                use_awaitable_t<Executor>{});

    rethrow_first_exception_if_any({ex0, ex1}, order);
    co_return std::move(detail::awaitable_unwrap<std::tuple<T...>>(r0));
}

//! Wait for both operations to succeed.
/**
 * If one operations fails, the other is cancelled as the AND-condition can no
 * longer be satisfied.
 */
template <typename... T, typename U, typename Executor>
awaitable<std::tuple<T..., U>, Executor> operator&&(
    awaitable<std::tuple<T...>, Executor> t, awaitable<U, Executor> u) {
    auto ex = co_await this_coro::executor;

    auto [order, ex0, r0, ex1, r1] =
        co_await make_parallel_group(
            co_spawn(ex, detail::awaitable_wrap(std::move(t)), deferred),
            co_spawn(ex, detail::awaitable_wrap(std::move(u)), deferred))
            .async_wait(
                wait_for_one_error(),
                use_awaitable_t<Executor>{});

    rethrow_first_exception_if_any({ex0, ex1}, order);
    co_return std::tuple_cat(
        std::move(detail::awaitable_unwrap<std::tuple<T...>>(r0)),
        std::make_tuple(std::move(detail::awaitable_unwrap<U>(r1))));
}

}  // namespace silkworm::concurrency::awaitable_wait_for_all
