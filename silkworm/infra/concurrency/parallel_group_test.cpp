// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <chrono>
#include <stdexcept>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>

using namespace boost::asio;
using namespace boost::asio::experimental;
using namespace silkworm::concurrency;
using namespace std::chrono_literals;

awaitable<void> my_sleep(std::chrono::milliseconds duration) {
    auto executor = co_await this_coro::executor;
    steady_timer timer(executor);
    timer.expires_after(duration);
    co_await timer.async_wait(use_awaitable);
}

awaitable<void> noop() {
    co_return;
}

awaitable<void> throw_op() {
    co_await my_sleep(1ms);
    throw std::runtime_error("throw_op");
}

awaitable<void> spawn_throw_op(strand<any_io_executor>& strand) {
    co_await spawn_task(strand, throw_op());
}

awaitable<void> spawn_noop_loop(strand<any_io_executor>& strand) {
    while (true) {
        co_await spawn_task(strand, noop());
    }
}

awaitable<void> co_spawn_cancellation_handler_bug() {
    using namespace awaitable_wait_for_all;
    auto executor = co_await boost::asio::this_coro::executor;
    auto strand = make_strand(executor);

    try {
        co_await (my_sleep(1s) && spawn_throw_op(strand) && spawn_noop_loop(strand));
    } catch (std::runtime_error&) {
    }
}

TEST_CASE("parallel_group.co_spawn_cancellation_handler_bug") {
    io_context ioc;
    spawn_future(ioc, co_spawn_cancellation_handler_bug());
    ioc.run();
}
