// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "awaitable_condition_variable.hpp"

#include <chrono>
#include <future>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/task_runner.hpp>

namespace silkworm::concurrency {

using namespace boost::asio;

TEST_CASE("AwaitableConditionVariable.not_blocking_when_notified_before_waiting") {
    test_util::TaskRunner runner;
    AwaitableConditionVariable cond_var;
    auto waiter = cond_var.waiter();

    cond_var.notify_all();
    runner.run(waiter());
}

TEST_CASE("AwaitableConditionVariable.blocks_during_waiting") {
    using namespace std::chrono_literals;

    test_util::TaskRunner runner;
    AwaitableConditionVariable cond_var;
    auto waiter = cond_var.waiter();

    // schedule waiting
    auto future = runner.spawn_future(waiter());
    // run until it blocks
    while (runner.ioc().poll_one() > 0) {
    }

    CHECK(future.wait_for(0s) == std::future_status::timeout);
}

TEST_CASE("AwaitableConditionVariable.notify_all_awakes_waiter") {
    test_util::TaskRunner runner;
    AwaitableConditionVariable cond_var;
    auto waiter = cond_var.waiter();

    // schedule waiting
    auto future = runner.spawn_future(waiter());
    // run until it blocks
    while (runner.ioc().poll_one() > 0) {
    }

    cond_var.notify_all();
    runner.poll_context_until_future_is_ready(future);
}

TEST_CASE("AwaitableConditionVariable.notify_all_awakes_multiple_waiters") {
    test_util::TaskRunner runner;
    AwaitableConditionVariable cond_var;
    auto waiter1 = cond_var.waiter();
    auto waiter2 = cond_var.waiter();
    auto waiter3 = cond_var.waiter();

    // schedule waiting
    auto future1 = runner.spawn_future(waiter1());
    auto future2 = runner.spawn_future(waiter2());
    auto future3 = runner.spawn_future(waiter3());
    // run until it blocks
    while (runner.ioc().poll_one() > 0) {
    }

    cond_var.notify_all();
    runner.poll_context_until_future_is_ready(future1);
    runner.poll_context_until_future_is_ready(future2);
    runner.poll_context_until_future_is_ready(future3);
}

}  // namespace silkworm::concurrency
