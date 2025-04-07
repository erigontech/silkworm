// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "spawn.hpp"

#include <chrono>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <catch2/catch_test_macros.hpp>

namespace silkworm::concurrency {

namespace asio = boost::asio;

Task<void> dummy_task() {
    auto executor = co_await asio::this_coro::executor;

    asio::steady_timer timer{executor};
    timer.expires_after(std::chrono::milliseconds(1));

    co_await timer.async_wait(asio::use_awaitable);
}

class DummyEngine {
    asio::io_context& ioc_;

  public:
    explicit DummyEngine(asio::io_context& ioc) : ioc_{ioc} {}

    static Task<int> do_work() {
        co_return 42;
    }

    asio::io_context& get_executor() {
        return ioc_;
    }
};

struct SpawnTest {
    SpawnTest() {
        ioc_thread = std::thread{[this]() { ioc.run(); }};
    }
    ~SpawnTest() {
        ioc.stop();
        if (ioc_thread.joinable()) {
            ioc_thread.join();
        }
    }

    asio::io_context ioc;
    asio::executor_work_guard<asio::io_context::executor_type> work_guard{ioc.get_executor()};
    std::thread ioc_thread;
};

TEST_CASE_METHOD(SpawnTest, "spawn_and_wait") {
    SECTION("wait for function") {
        CHECK_NOTHROW(spawn_future_and_wait(ioc, dummy_task()));
    }

    SECTION("wait for method") {
        DummyEngine engine{ioc};
        CHECK(spawn_future_and_wait(engine.get_executor(), DummyEngine::do_work()) == 42);
    }
}

}  // namespace silkworm::concurrency