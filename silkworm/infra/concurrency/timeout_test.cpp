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

#include "timeout.hpp"

#include <exception>
#include <stdexcept>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/multiple_exceptions.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/system_error.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/test_util/task_runner.hpp>

namespace silkworm::concurrency {

using namespace std::chrono_literals;
using namespace boost::asio;

class TestException : public std::runtime_error {
  public:
    TestException() : std::runtime_error("TestException") {}
};

template <typename T>
Task<T> async_value(T value) {
    co_await this_coro::executor;
    co_return value;
}

Task<bool> async_ok() {
    return async_value(true);
}

Task<void> async_throw() {
    co_await this_coro::executor;
    throw TestException();
}

Task<void> short_timeout() {
    co_await timeout(1ms);
}

Task<void> simple_timeout() {
    co_await timeout(1h);
}

Task<void> wait_until_cancelled() {
    auto executor = co_await this_coro::executor;
    steady_timer timer(executor);
    timer.expires_after(1h);
    co_await timer.async_wait(use_awaitable);
}

class BadCancelException : public std::runtime_error {
  public:
    BadCancelException() : std::runtime_error("BadCancelException") {}
};

Task<void> wait_until_cancelled_bad() {
    try {
        auto executor = co_await this_coro::executor;
        steady_timer timer(executor);
        timer.expires_after(1h);
        co_await timer.async_wait(use_awaitable);
    } catch (const boost::system::system_error&) {
        throw BadCancelException();
    }
}

template <typename TResult>
TResult run(Task<TResult> task) {
    test_util::TaskRunner runner;
    return runner.run(std::move(task));
}

TEST_CASE("Timeout.value") {
    CHECK(run(async_value(123)) == 123);
}

TEST_CASE("Timeout.ok") {
    CHECK(run(async_ok()));
}

TEST_CASE("Timeout.throw") {
    CHECK_THROWS_AS(run(async_throw()), TestException);
}

TEST_CASE("Timeout.timeout") {
    CHECK_THROWS_AS(run(short_timeout()), TimeoutExpiredError);
}

TEST_CASE("Timeout.boost_wait_for_one.throw_or_timeout") {
    using namespace boost::asio::experimental::awaitable_operators;
    CHECK_THROWS_AS(run(async_throw() || short_timeout()), multiple_exceptions);
}

TEST_CASE("Timeout.boost_wait_for_one.timeout_or_throw") {
    using namespace boost::asio::experimental::awaitable_operators;
    CHECK_THROWS_AS(run(short_timeout() || async_throw()), multiple_exceptions);
}

TEST_CASE("Timeout.boost_wait_for_all.cancel_and_throw") {
    using namespace boost::asio::experimental::awaitable_operators;
    CHECK_THROWS_AS(run(wait_until_cancelled() && async_throw()), multiple_exceptions);
}

TEST_CASE("Timeout.boost_wait_for_all.throw_and_cancel") {
    using namespace boost::asio::experimental::awaitable_operators;
    CHECK_THROWS_AS(run(async_throw() && wait_until_cancelled()), multiple_exceptions);
}

TEST_CASE("Timeout.wait_for_one.ok_or_value") {
    using namespace awaitable_wait_for_one;
    auto result = run(async_ok() || async_value(123));
    CHECK(std::get<bool>(result));
}

TEST_CASE("Timeout.wait_for_one.value_or_ok") {
    using namespace awaitable_wait_for_one;
    auto result = run(async_value(123) || async_ok());
    CHECK(std::get<int>(result) == 123);
}

TEST_CASE("Timeout.wait_for_one.ok_or_timeout") {
    using namespace awaitable_wait_for_one;
    auto result = run(async_ok() || simple_timeout());
    CHECK(std::get<bool>(result));
}

TEST_CASE("Timeout.wait_for_one.timeout_or_ok") {
    using namespace awaitable_wait_for_one;
    auto result = run(simple_timeout() || async_ok());
    CHECK(std::get<bool>(result));
}

TEST_CASE("Timeout.wait_for_one.throw_or_timeout") {
    using namespace awaitable_wait_for_one;
    CHECK_THROWS_AS(run(async_throw() || simple_timeout()), TestException);
}

TEST_CASE("Timeout.wait_for_one.timeout_or_throw") {
    using namespace awaitable_wait_for_one;
    CHECK_THROWS_AS(run(simple_timeout() || async_throw()), TestException);
}

TEST_CASE("Timeout.wait_for_one.cancel_and_throw") {
    using namespace awaitable_wait_for_one;
    CHECK_THROWS_AS(run(wait_until_cancelled() || async_throw()), TestException);
}

TEST_CASE("Timeout.wait_for_one.throw_and_cancel") {
    using namespace awaitable_wait_for_one;
    CHECK_THROWS_AS(run(async_throw() || wait_until_cancelled()), TestException);
}

TEST_CASE("Timeout.wait_for_all.ok_and_value") {
    using namespace awaitable_wait_for_all;
    auto [ok, value] = run(async_ok() && async_value(123));
    CHECK(ok);
    CHECK(value == 123);
}

TEST_CASE("Timeout.wait_for_all.value_and_ok") {
    using namespace awaitable_wait_for_all;
    auto [value, ok] = run(async_value(123) && async_ok());
    CHECK(value == 123);
    CHECK(ok);
}

TEST_CASE("Timeout.wait_for_all.ok_and_throw") {
    using namespace awaitable_wait_for_all;
    CHECK_THROWS_AS(run(async_ok() && async_throw()), TestException);
}

TEST_CASE("Timeout.wait_for_all.throw_and_ok") {
    using namespace awaitable_wait_for_all;
    CHECK_THROWS_AS(run(async_throw() && async_ok()), TestException);
}

TEST_CASE("Timeout.wait_for_all.timeout_and_throw") {
    using namespace awaitable_wait_for_all;
    CHECK_THROWS_AS(run(simple_timeout() && async_throw()), TestException);
}

TEST_CASE("Timeout.wait_for_all.throw_and_timeout") {
    using namespace awaitable_wait_for_all;
    CHECK_THROWS_AS(run(async_throw() && simple_timeout()), TestException);
}

TEST_CASE("Timeout.wait_for_all.cancel_and_throw") {
    using namespace awaitable_wait_for_all;
    CHECK_THROWS_AS(run(wait_until_cancelled() && async_throw()), TestException);
}

TEST_CASE("Timeout.wait_for_all.throw_and_cancel") {
    using namespace awaitable_wait_for_all;
    CHECK_THROWS_AS(run(async_throw() && wait_until_cancelled()), TestException);
}

TEST_CASE("Timeout.wait_for_all.bad_cancel_and_throw") {
    using namespace awaitable_wait_for_all;
    try {
        run(wait_until_cancelled_bad() && async_throw());
        CHECK(false);
    } catch (const std::exception& ex) {
        CHECK(std::string(ex.what()) == "BadCancelException");
        CHECK_THROWS_AS(std::rethrow_if_nested(ex), TestException);
    }
}

TEST_CASE("Timeout.wait_for_all.throw_and_bad_cancel") {
    using namespace awaitable_wait_for_all;
    try {
        run(async_throw() && wait_until_cancelled_bad());
        CHECK(false);
    } catch (const std::exception& ex) {
        CHECK(std::string(ex.what()) == "BadCancelException");
        CHECK_THROWS_AS(std::rethrow_if_nested(ex), TestException);
    }
}

}  // namespace silkworm::concurrency
