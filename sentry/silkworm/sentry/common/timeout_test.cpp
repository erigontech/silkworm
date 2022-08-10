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

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/multiple_exceptions.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch.hpp>

#include "awaitable_wait_for_one.hpp"

namespace silkworm::sentry::common {

using namespace std::chrono_literals;
using namespace boost::asio;

class TestException : public std::runtime_error {
  public:
    TestException() : std::runtime_error("TestException") {}
};

awaitable<bool> async_ok() {
    co_await this_coro::executor;
    co_return true;
}

awaitable<void> async_throw() {
    co_await this_coro::executor;
    throw TestException();
}

template <typename TResult>
TResult run(awaitable<TResult> awaitable1) {
    io_context context;
    auto task = co_spawn(
        context,
        std::move(awaitable1),
        boost::asio::use_future);

    while (task.wait_for(0s) == std::future_status::timeout) {
        context.poll_one();
    }

    return task.get();
}

awaitable<void> simple_timeout() {
    Timeout timeout(1ms);
    co_await timeout();
}

TEST_CASE("Timeout.simple_timeout") {
    CHECK_THROWS_AS(run(simple_timeout()), Timeout::ExpiredError);
}

TEST_CASE("Timeout.co_await_catch") {
    CHECK_THROWS_AS(run(async_throw()), TestException);
}

awaitable<void> throw_and_timeout() {
    using namespace boost::asio::experimental::awaitable_operators;
    Timeout timeout(1s);
    co_await (async_throw() && timeout());
}

TEST_CASE("Timeout.throw_and_timeout") {
    CHECK_THROWS_AS(run(throw_and_timeout()), TestException);
}

awaitable<void> throw_or_timeout_boost() {
    using namespace boost::asio::experimental::awaitable_operators;
    Timeout timeout(1ms);
    co_await (async_throw() || timeout());
}

TEST_CASE("Timeout.throw_or_timeout_boost") {
    CHECK_THROWS_AS(run(throw_or_timeout_boost()), multiple_exceptions);
}

awaitable<void> throw_or_timeout_wait_for_one() {
    using namespace awaitable_wait_for_one;
    Timeout timeout(1s);
    co_await (async_throw() || timeout());
}

TEST_CASE("Timeout.throw_or_timeout_wait_for_one") {
    CHECK_THROWS_AS(run(throw_or_timeout_wait_for_one()), TestException);
}

awaitable<bool> ok_or_timeout_wait_for_one() {
    using namespace awaitable_wait_for_one;
    Timeout timeout(1s);
    auto result_var = co_await (async_ok() || timeout());
    bool result = std::get<bool>(result_var);
    co_return result;
}

TEST_CASE("Timeout.ok_or_timeout_wait_for_one") {
    CHECK(run(ok_or_timeout_wait_for_one()));
}

}  // namespace silkworm::sentry::common
