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

#include <catch2/catch.hpp>

#include "active_component.hpp"

namespace silkworm {

namespace asio = boost::asio;
using concurrency::AwaitableFuture;
using concurrency::AwaitablePromise;

class IOExecution : public ActiveComponent {
  public:
    IOExecution(asio::io_context& io) : io_(io) {
        thread_ = std::thread{[this] { execution_loop(); }};
    }
    void wait_exiting() { thread_.join(); }
    ~IOExecution() {
        stop();
        wait_exiting();
    }

  private:
    virtual void execution_loop() {
        while (!is_stopping()) io_.run();
    }

    asio::io_context& io_;
    std::thread thread_;
};

auto create_promise_and_set_value(asio::io_context& io, int value) {
    concurrency::AwaitablePromise<int> promise{io};
    promise.set_value(value);
    return promise.get_future();
}

TEST_CASE("awaitable future") {
    asio::io_context io;
    IOExecution execution{io};

    SECTION("blocking get - normal") {
        AwaitablePromise<int> promise{io};
        auto future = promise.get_future();

        promise.set_value(42);
        auto value = future.get();

        CHECK(value == 42);

        // The destructor of Executor calls stop() and join()
    }

    SECTION("blocking get - exception") {
        AwaitablePromise<int> promise{io};
        auto future = promise.get_future();

        promise.set_exception(std::make_exception_ptr(new std::exception()));

        CHECK_THROWS(future.get());
    }

    SECTION("blocking get - promise destroyed first (1)") {
        auto future = create_promise_and_set_value(io, 42);

        auto value = future.get();

        CHECK(value == 42);
    }

    SECTION("blocking get - promise destroyed first (2)") {
        auto get_future = [&]() {
            concurrency::AwaitablePromise<int> promise{io};
            auto future = promise.get_future();
            promise.set_value(42);
            return future;
        }();

        auto value = get_future.get();

        CHECK(value == 42);
    }

    SECTION("blocking get - movable future") {
        AwaitablePromise<int> promise{io};
        auto future = promise.get_future();

        int value;
        std::thread concurrent([&](AwaitableFuture<int>&& moved_future) {
            value = moved_future.get();
        },
                               std::move(future));

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        promise.set_value(42);
        concurrent.join();

        CHECK(value == 42);
    }

    SECTION("awaitable get") {
        AwaitablePromise<int> promise{io};
        int value;

        auto spawned_exec = asio::co_spawn(
            io,
            [&]() -> asio::awaitable<void> {
                auto future = promise.get_future();
                value = co_await future.get(asio::use_awaitable);
            },
            asio::use_future);

        promise.set_value(42);
        spawned_exec.get();

        CHECK(value == 42);
    }

    SECTION("awaitable get - movable future") {
        AwaitablePromise<int> promise{io};
        auto future = promise.get_future();

        int value;
        auto spawned_exec = asio::co_spawn(
            io,
            [&](AwaitableFuture<int>&& moved_future) -> asio::awaitable<void> {
                value = co_await moved_future.get(asio::use_awaitable);
            }(std::move(future)),
            asio::use_future);

        promise.set_value(42);
        spawned_exec.get();

        CHECK(value == 42);
    }

    SECTION("blocking set / awaitable get") {
        AwaitablePromise<int> promise{io};
        int value;

        auto spawned_exec = asio::co_spawn(
            io,
            [&]() -> asio::awaitable<void> {
                auto future = promise.get_future();
                value = co_await future.get(asio::use_awaitable);
            },
            asio::use_future);

        promise.set_value(42, asio::use_future).get();
        spawned_exec.get();

        CHECK(value == 42);
    }

    SECTION("awaiting forever on get") {
        AwaitablePromise<int> promise{io};
        int value = 0;

        auto spawned_exec = asio::co_spawn(
            io,
            [&]() -> asio::awaitable<void> {
                auto future = promise.get_future();
                value = co_await future.get(asio::use_awaitable);
            },
            asio::use_future);

        spawned_exec.wait_for(std::chrono::milliseconds(100));

        CHECK(value == 0);
    }
}

}  // namespace silkworm