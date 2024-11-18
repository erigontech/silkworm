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