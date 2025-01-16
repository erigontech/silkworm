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
#include <stdexcept>
#include <string_view>

#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/test_util/task_runner.hpp>

namespace silkworm::concurrency {

using namespace boost::asio;
using namespace std::chrono_literals;
using namespace awaitable_wait_for_all;

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
    } catch (const boost::system::system_error&) {
        *is_cancelled = true;
    }
}

static Task<void> sleep(std::chrono::milliseconds duration) {
    auto executor = co_await this_coro::executor;
    steady_timer timer(executor);
    timer.expires_after(duration);
    co_await timer.async_wait(use_awaitable);
}

TEST_CASE("TaskGroup.0") {
    test_util::TaskRunner runner;
    auto executor = runner.executor();
    TaskGroup group{executor, 0};
    CHECK_THROWS_AS(runner.run(group.wait() && async_throw()), TestException);
}

TEST_CASE("TaskGroup.1") {
    test_util::TaskRunner runner;
    auto executor = runner.executor();
    TaskGroup group{executor, 1};
    group.spawn(executor, async_ok());
    CHECK_THROWS_AS(runner.run(group.wait() && async_throw()), TestException);
}

TEST_CASE("TaskGroup.1.wait_until_cancelled") {
    test_util::TaskRunner runner;
    auto executor = runner.executor();
    TaskGroup group{executor, 1};
    bool is_cancelled = false;
    group.spawn(executor, wait_until_cancelled(&is_cancelled));
    CHECK_THROWS_AS(runner.run(group.wait() && async_throw()), TestException);
    CHECK(is_cancelled);
}

TEST_CASE("TaskGroup.some.wait_until_cancelled") {
    test_util::TaskRunner runner;
    auto executor = runner.executor();
    TaskGroup group{executor, 3};
    std::array<bool, 3> is_cancelled{};
    group.spawn(executor, wait_until_cancelled(&is_cancelled[0]));
    group.spawn(executor, wait_until_cancelled(&is_cancelled[1]));
    group.spawn(executor, wait_until_cancelled(&is_cancelled[2]));
    CHECK_THROWS_AS(runner.run(group.wait() && async_throw()), TestException);
    CHECK(is_cancelled[0]);
    CHECK(is_cancelled[1]);
    CHECK(is_cancelled[2]);
}

TEST_CASE("TaskGroup.some.mix") {
    test_util::TaskRunner runner;
    auto executor = runner.executor();
    TaskGroup group{executor, 6};
    std::array<bool, 3> is_cancelled{};
    group.spawn(executor, async_ok());
    group.spawn(executor, wait_until_cancelled(&is_cancelled[0]));
    group.spawn(executor, async_ok());
    group.spawn(executor, wait_until_cancelled(&is_cancelled[1]));
    group.spawn(executor, async_ok());
    group.spawn(executor, wait_until_cancelled(&is_cancelled[2]));
    CHECK_THROWS_AS(runner.run(group.wait() && async_throw()), TestException);
    CHECK(is_cancelled[0]);
    CHECK(is_cancelled[1]);
    CHECK(is_cancelled[2]);
}

TEST_CASE("TaskGroup.spawn_after_close") {
    test_util::TaskRunner runner;
    auto executor = runner.executor();
    TaskGroup group{executor, 1};
    CHECK_THROWS_AS(runner.run(group.wait() && async_throw()), TestException);
    CHECK_THROWS_AS(group.spawn(executor, async_ok()), TaskGroup::SpawnAfterCloseError);
}

TEST_CASE("TaskGroup.task_exception_is_rethrown") {
    test_util::TaskRunner runner;
    auto executor = runner.executor();
    TaskGroup group{executor, 1};
    group.spawn(executor, async_throw());

    auto test = [&]() -> Task<bool> {
        try {
            co_await group.wait();
            co_return false;
        } catch (const TestException&) {
            co_return true;
        }
    };
    CHECK(runner.run(test()));
}

TEST_CASE("TaskGroup.task_cancelled_exception_is_ignored") {
    using namespace awaitable_wait_for_one;

    test_util::TaskRunner runner;
    auto executor = runner.executor();
    TaskGroup group{executor, 1};

    auto task = [&]() -> Task<void> {
        co_await boost::asio::this_coro::executor;
        throw boost::system::system_error(make_error_code(boost::system::errc::operation_canceled));
    };
    group.spawn(executor, task());

    CHECK_NOTHROW(runner.run(group.wait() || sleep(1ms)));
}

TEST_CASE("TaskGroup.task_exception_during_cancellation_is_rethrown") {
    test_util::TaskRunner runner;
    auto executor = runner.executor();
    TaskGroup group{executor, 1};

    auto task = [&]() -> Task<void> {
        bool is_cancelled = false;
        co_await wait_until_cancelled(&is_cancelled);
        if (is_cancelled) {
            throw std::runtime_error("exception_during_cancellation");
        }
    };
    group.spawn(executor, task());
    group.spawn(executor, async_throw());

    auto test = [&]() -> Task<bool> {
        try {
            co_await group.wait();
            co_return false;
        } catch (const TestException&) {
            co_return false;
        } catch (const std::runtime_error& ex) {
            co_return (ex.what() == std::string_view{"exception_during_cancellation"});
        }
    };
    CHECK(runner.run(test()));
}

}  // namespace silkworm::concurrency
