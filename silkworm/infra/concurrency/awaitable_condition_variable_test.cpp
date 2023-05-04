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

#include "awaitable_condition_variable.hpp"

#include <chrono>
#include <future>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch.hpp>

namespace silkworm::concurrency {

using namespace boost::asio;
using namespace std::chrono_literals;

template <typename TResult>
static void poll_context_until_future_is_ready(io_context& context, std::future<TResult>& future) {
    while (future.wait_for(0s) != std::future_status::ready) {
        context.poll_one();
    }
}

template <typename TResult>
static TResult run(io_context& context, awaitable<TResult> awaitable1) {
    auto task = co_spawn(context, std::move(awaitable1), use_future);
    poll_context_until_future_is_ready(context, task);
    return task.get();
}

TEST_CASE("AwaitableConditionVariable.not_blocking_when_notified_before_waiting") {
    io_context context;
    AwaitableConditionVariable cond_var;
    auto waiter = cond_var.waiter();

    cond_var.notify_all();
    run(context, waiter());
}

TEST_CASE("AwaitableConditionVariable.blocks_during_waiting") {
    io_context context;
    AwaitableConditionVariable cond_var;
    auto waiter = cond_var.waiter();

    // schedule waiting
    auto task = co_spawn(context, waiter(), use_future);
    // run until it blocks
    while (context.poll_one() > 0) {
    }

    CHECK(task.wait_for(0s) == std::future_status::timeout);
}

TEST_CASE("AwaitableConditionVariable.notify_all_awakes_waiter") {
    io_context context;
    AwaitableConditionVariable cond_var;
    auto waiter = cond_var.waiter();

    // schedule waiting
    auto task = co_spawn(context, waiter(), use_future);
    // run until it blocks
    while (context.poll_one() > 0) {
    }

    cond_var.notify_all();
    poll_context_until_future_is_ready(context, task);
}

TEST_CASE("AwaitableConditionVariable.notify_all_awakes_multiple_waiters") {
    io_context context;
    AwaitableConditionVariable cond_var;
    auto waiter1 = cond_var.waiter();
    auto waiter2 = cond_var.waiter();
    auto waiter3 = cond_var.waiter();

    // schedule waiting
    auto task1 = co_spawn(context, waiter1(), use_future);
    auto task2 = co_spawn(context, waiter2(), use_future);
    auto task3 = co_spawn(context, waiter3(), use_future);
    // run until it blocks
    while (context.poll_one() > 0) {
    }

    cond_var.notify_all();
    poll_context_until_future_is_ready(context, task1);
    poll_context_until_future_is_ready(context, task2);
    poll_context_until_future_is_ready(context, task3);
}

}  // namespace silkworm::concurrency
