// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "awaitable_future.hpp"

#include <stdexcept>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/task_runner.hpp>

#include "active_component.hpp"

namespace silkworm {

namespace asio = boost::asio;
using concurrency::AwaitableFuture;
using concurrency::AwaitablePromise;

auto create_promise_and_set_value(const asio::any_io_executor& executor, int value) {
    concurrency::AwaitablePromise<int> promise{executor};
    promise.set_value(value);
    return promise.get_future();
}

class TestException : public std::runtime_error {
  public:
    TestException() : std::runtime_error("TestException") {}
};

TEST_CASE("awaitable future") {
    test_util::TaskRunner runner;
    AwaitablePromise<int> promise{runner.executor()};

    SECTION("trivial use") {
        auto future = promise.get_future();

        promise.set_value(42);
        auto value = runner.run(future.get());

        CHECK(value == 42);
    }

    SECTION("variation of the trivial use") {
        promise.set_value(42);

        auto future = promise.get_future();
        auto value = runner.run(future.get());

        CHECK(value == 42);
    }

    SECTION("setting exception instead of value") {
        auto future = promise.get_future();

        promise.set_exception(std::make_exception_ptr(TestException()));

        CHECK_THROWS_AS(runner.run(future.get()), TestException);
    }

    SECTION("variation of setting exception instead of value") {
        auto future = promise.get_future();

        try {
            throw TestException();
        } catch (const TestException&) {
            promise.set_exception(std::current_exception());
        }

        CHECK_THROWS_AS(runner.run(future.get()), TestException);
    }

    SECTION("setting value two times fails") {
        promise.set_value(42);

        CHECK_THROWS(promise.set_value(43));
    }

    SECTION("setting exception two times fails") {
        promise.set_exception(std::make_exception_ptr(TestException()));

        CHECK_THROWS(promise.set_exception(std::make_exception_ptr(TestException())));
    }

    SECTION("returning the future from a function") {
        auto future = create_promise_and_set_value(runner.executor(), 42);

        auto value = runner.run(future.get());

        CHECK(value == 42);
    }

    SECTION("returning the future from a function (variation)") {
        auto returned_future = [executor = runner.executor()]() {
            concurrency::AwaitablePromise<int> promise1{executor};
            auto future = promise1.get_future();
            promise1.set_value(42);
            return future;
        }();

        auto value = runner.run(returned_future.get());

        CHECK(value == 42);
    }

    SECTION("writing and reading from different threads") {
        int value{0};
        std::thread concurrent(
            [&](AwaitableFuture<int> moved_future) {
                value = runner.run(moved_future.get());
            },
            promise.get_future());

        promise.set_value(42);

        concurrent.join();

        CHECK(value == 42);
    }

    SECTION("writing and reading from different threads") {
        int value{0};
        std::thread concurrent(
            [&](AwaitableFuture<int> moved_future) {
                value = runner.run(moved_future.get());
            },
            promise.get_future());

        runner.run(
            [&]() -> Task<void> {
                promise.set_value(42);
                co_return;
            }());

        concurrent.join();

        CHECK(value == 42);
    }

    SECTION("using coroutines in read in the same io_context, write before read") {
        int value{0};

        promise.set_value(42);

        runner.run(
            [&]() -> Task<void> {
                auto future = promise.get_future();
                value = co_await future.get();
            }());

        CHECK(value == 42);
    }

    SECTION("variation of using coroutines in the same io_context, write before read") {
        auto future = promise.get_future();

        promise.set_value(42);

        int value{0};
        runner.run(
            [&]() -> Task<void> {
                value = co_await future.get();
            }());

        CHECK(value == 42);
    }

    SECTION("moving AwaitableFuture") {
        auto future = promise.get_future();

        int value{0};
        auto lambda = [&](AwaitableFuture<int> moved_future) -> Task<void> {
            value = co_await moved_future.get();
        };

        promise.set_value(42);
        runner.run(lambda(std::move(future)));

        CHECK(value == 42);
    }

    SECTION("using coroutine for both read and write, read before write") {
        asio::io_context& ioc = runner.ioc();
        int value{0};

        asio::co_spawn(
            ioc,
            [&]() -> Task<void> {
                auto future = promise.get_future();
                value = co_await future.get();
                ioc.stop();
            },
            asio::detached);

        asio::co_spawn(
            ioc,
            [&]() -> Task<void> {
                promise.set_value(42);
                co_return;
            },
            asio::detached);

        ioc.run();

        CHECK(value == 42);
    }

    SECTION("cancellation after read") {
        asio::io_context& ioc = runner.ioc();
        int value{0};
        boost::system::error_code code;

        boost::asio::cancellation_signal cancellation_signal;
        asio::co_spawn(
            ioc,
            [&]() -> Task<void> {
                auto future = promise.get_future();
                try {
                    value = co_await future.get();
                } catch (const boost::system::system_error& se) {
                    code = se.code();
                }
                ioc.stop();
            },
            boost::asio::bind_cancellation_slot(cancellation_signal.slot(), asio::detached));

        asio::co_spawn(
            ioc,
            [&]() -> Task<void> {
                cancellation_signal.emit(boost::asio::cancellation_type::all);
                co_return;
            },
            asio::detached);

        ioc.run();

        CHECK(promise.set_value(42) == false);
        CHECK(code == boost::system::errc::operation_canceled);
    }
}

}  // namespace silkworm