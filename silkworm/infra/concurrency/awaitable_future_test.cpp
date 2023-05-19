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

#include "awaitable_future.hpp"

#include <stdexcept>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <catch2/catch.hpp>

#include "active_component.hpp"

namespace silkworm {

namespace asio = boost::asio;
using concurrency::AwaitableFuture;
using concurrency::AwaitablePromise;

auto create_promise_and_set_value(asio::io_context& io, int value) {
    concurrency::AwaitablePromise<int> promise{io};
    promise.set_value(value);
    return promise.get_future();
}

class TestException : public std::runtime_error {
  public:
    TestException() : std::runtime_error("TestException") {}
};

TEST_CASE("awaitable future") {
    asio::io_context io;
    asio::io_context::work work{io};

    SECTION("trivial use") {
        AwaitablePromise<int> promise{io};

        auto future = promise.get_future();

        promise.set_value(42);
        auto value = future.get();

        CHECK(value == 42);
    }

    SECTION("variation of the trivial use") {
        AwaitablePromise<int> promise{io};
        promise.set_value(42);

        auto future = promise.get_future();
        auto value = future.get();

        CHECK(value == 42);
    }

    SECTION("setting exception instead of value") {
        AwaitablePromise<int> promise{io};
        auto future = promise.get_future();

        promise.set_exception(std::make_exception_ptr(TestException()));

        CHECK_THROWS_AS(future.get(), TestException);
    }

    SECTION("variation of setting exception instead of value") {
        AwaitablePromise<int> promise{io};
        auto future = promise.get_future();

        try {
            throw TestException();
        } catch (const TestException&) {
            promise.set_exception(std::current_exception());
        }

        CHECK_THROWS_AS(future.get(), TestException);
    }

    SECTION("setting value two times fails") {
        AwaitablePromise<int> promise{io};

        promise.set_value(42);

        CHECK_THROWS(promise.set_value(43));
    }

    SECTION("setting exception two times fails") {
        AwaitablePromise<int> promise{io};

        promise.set_exception(std::make_exception_ptr(TestException()));

        CHECK_THROWS(promise.set_exception(std::make_exception_ptr(TestException())));
    }

    SECTION("returning the future from a function") {
        auto future = create_promise_and_set_value(io, 42);

        auto value = future.get();

        CHECK(value == 42);
    }

    SECTION("returning the future from a function (variation)") {
        auto returned_future = [&]() {
            concurrency::AwaitablePromise<int> promise{io};
            auto future = promise.get_future();
            promise.set_value(42);
            return future;
        }();

        auto value = returned_future.get();

        CHECK(value == 42);
    }

    SECTION("writing and reading from different threads") {
        AwaitablePromise<int> promise{io};
        auto future = promise.get_future();

        int value;
        std::thread concurrent(
            [&](AwaitableFuture<int>&& moved_future) {
                value = moved_future.get();
                io.stop();
            },
            std::move(future));

        promise.set_value(42);

        io.run();
        concurrent.join();

        CHECK(value == 42);
    }

    SECTION("writing and reading from different threads") {
        AwaitablePromise<int> promise{io};
        auto future = promise.get_future();

        int value;
        std::thread concurrent(
            [&](AwaitableFuture<int>&& moved_future) {
                value = moved_future.get();
                io.stop();
            },
            std::move(future));

        asio::co_spawn(
            io,
            [&]() -> asio::awaitable<void> {
                promise.set_value(42);
                co_return;
            },
            asio::detached);

        io.run();
        concurrent.join();

        CHECK(value == 42);
    }

    SECTION("using coroutines in read in the same io_context, write before read") {
        AwaitablePromise<int> promise{io};
        int value;

        asio::co_spawn(
            io,
            [&]() -> asio::awaitable<void> {
                auto future = promise.get_future();
                value = co_await future.get_async();
                io.stop();
            },
            asio::detached);

        promise.set_value(42);
        io.run();

        CHECK(value == 42);
    }

    SECTION("variation of using coroutines in the same io_context, write before read") {
        AwaitablePromise<int> promise{io};
        auto future = promise.get_future();

        int value;
        asio::co_spawn(
            io,
            [&]() -> asio::awaitable<void> {
                value = co_await future.get_async();
                io.stop();
            },
            asio::detached);

        promise.set_value(42);
        io.run();

        CHECK(value == 42);
    }

    SECTION("moving AwaitableFuture") {
        AwaitablePromise<int> promise{io};
        auto future = promise.get_future();

        int value;
        auto lambda = [&](AwaitableFuture<int>&& moved_future) -> asio::awaitable<void> {
            value = co_await moved_future.get_async();
            io.stop();
        };

        asio::co_spawn(io, lambda(std::move(future)), asio::detached);

        promise.set_value(42);
        io.run();

        CHECK(value == 42);
    }

    SECTION("using coroutine for both read and write, read before write") {
        AwaitablePromise<int> promise{io};
        int value;

        asio::co_spawn(
            io,
            [&]() -> asio::awaitable<void> {
                auto future = promise.get_future();
                value = co_await future.get_async();
                io.stop();
            },
            asio::detached);

        asio::co_spawn(
            io,
            [&]() -> asio::awaitable<void> {
                promise.set_value(42);
                co_return;
            },
            asio::detached);

        io.run();

        CHECK(value == 42);
    }
}

}  // namespace silkworm