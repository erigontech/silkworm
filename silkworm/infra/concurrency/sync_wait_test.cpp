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

#include "sync_wait.hpp"

#include <chrono>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <catch2/catch_test_macros.hpp>

namespace silkworm {

namespace asio = boost::asio;

Task<void> dummy_task() {
    auto executor = co_await asio::this_coro::executor;

    asio::steady_timer timer{executor};
    timer.expires_after(std::chrono::milliseconds(1));

    co_await timer.async_wait(asio::use_awaitable);
}

class DummyEngine {
    asio::io_context& io_;

  public:
    DummyEngine(asio::io_context& io) : io_{io} {}

    static Task<int> do_work() {
        co_return 42;
    }

    asio::io_context& get_executor() {
        return io_;
    }
};

TEST_CASE("sync wait") {
    asio::io_context io;
    asio::executor_work_guard<asio::io_context::executor_type> work_guard{io.get_executor()};

    SECTION("wait for function") {
        std::thread io_execution([&io]() { io.run(); });

        sync_wait(io, dummy_task());

        io.stop();
        io_execution.join();
    }

    SECTION("wait for method") {
        std::thread io_execution([&io]() { io.run(); });

        DummyEngine engine{io};

        auto value = sync_wait(in(engine), DummyEngine::do_work());

        CHECK(value == 42);

        io.stop();
        io_execution.join();
    }
}

}  // namespace silkworm