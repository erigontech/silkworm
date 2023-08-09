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

#include "task_group.hpp"

#include <array>
#include <chrono>
#include <future>
#include <stdexcept>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/system/system_error.hpp>
#include <catch2/catch.hpp>

#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>

namespace silkworm::concurrency {

using namespace boost::asio;
using namespace std::chrono_literals;
using namespace concurrency::awaitable_wait_for_all;

static Task<void> async_ok() {
    co_await this_coro::executor;
}

class TestException : public std::runtime_error {
  public:
    TestException() : std::runtime_error("TestException") {}
};

static Task<void> async_throw() {
    co_await this_coro::executor;
    throw TestException();
}

static Task<void> wait_until_cancelled(bool* is_cancelled) {
    try {
        auto executor = co_await this_coro::executor;
        steady_timer timer(executor);
        timer.expires_after(1h);
        co_await timer.async_wait(use_awaitable);
    } catch (const boost::system::system_error& ex) {
        *is_cancelled = true;
    }
}

template <typename TResult>
static TResult run(io_context& context, Task<TResult> awaitable1) {
    auto task = co_spawn(
        context,
        std::move(awaitable1),
        use_future);

    while (task.wait_for(0s) == std::future_status::timeout) {
        context.poll_one();
    }

    return task.get();
}

TEST_CASE("TaskGroup.0") {
    io_context context;
    auto executor = context.get_executor();
    TaskGroup group{executor, 0};
    CHECK_THROWS_AS(run(context, group.wait() && async_throw()), TestException);
}

TEST_CASE("TaskGroup.1") {
    io_context context;
    auto executor = context.get_executor();
    TaskGroup group{executor, 1};
    group.spawn(executor, async_ok());
    CHECK_THROWS_AS(run(context, group.wait() && async_throw()), TestException);
}

TEST_CASE("TaskGroup.1.wait_until_cancelled") {
    io_context context;
    auto executor = context.get_executor();
    TaskGroup group{executor, 1};
    bool is_cancelled = false;
    group.spawn(executor, wait_until_cancelled(&is_cancelled));
    CHECK_THROWS_AS(run(context, group.wait() && async_throw()), TestException);
    CHECK(is_cancelled);
}

TEST_CASE("TaskGroup.some.wait_until_cancelled") {
    io_context context;
    auto executor = context.get_executor();
    TaskGroup group{executor, 3};
    std::array<bool, 3> is_cancelled{};
    group.spawn(executor, wait_until_cancelled(&is_cancelled[0]));
    group.spawn(executor, wait_until_cancelled(&is_cancelled[1]));
    group.spawn(executor, wait_until_cancelled(&is_cancelled[2]));
    CHECK_THROWS_AS(run(context, group.wait() && async_throw()), TestException);
    CHECK(is_cancelled[0]);
    CHECK(is_cancelled[1]);
    CHECK(is_cancelled[2]);
}

TEST_CASE("TaskGroup.some.mix") {
    io_context context;
    auto executor = context.get_executor();
    TaskGroup group{executor, 6};
    std::array<bool, 3> is_cancelled{};
    group.spawn(executor, async_ok());
    group.spawn(executor, wait_until_cancelled(&is_cancelled[0]));
    group.spawn(executor, async_ok());
    group.spawn(executor, wait_until_cancelled(&is_cancelled[1]));
    group.spawn(executor, async_ok());
    group.spawn(executor, wait_until_cancelled(&is_cancelled[2]));
    CHECK_THROWS_AS(run(context, group.wait() && async_throw()), TestException);
    CHECK(is_cancelled[0]);
    CHECK(is_cancelled[1]);
    CHECK(is_cancelled[2]);
}

TEST_CASE("TaskGroup.spawn_after_close") {
    io_context context;
    auto executor = context.get_executor();
    TaskGroup group{executor, 1};
    CHECK_THROWS_AS(run(context, group.wait() && async_throw()), TestException);
    CHECK_THROWS_AS(group.spawn(executor, async_ok()), TaskGroup::SpawnAfterCloseError);
}

}  // namespace silkworm::concurrency
