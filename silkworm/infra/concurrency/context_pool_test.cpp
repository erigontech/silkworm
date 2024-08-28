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

#include "context_pool.hpp"

#include <atomic>
#include <stdexcept>
#include <thread>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/executor_work_guard.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/test_util/null_stream.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/sleep.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::concurrency {

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
#ifndef SILKWORM_SANITIZE
TEST_CASE("Context", "[silkworm][concurrency][server_context]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    Context ctx{0};

    SECTION("ServerContext") {
        CHECK(ctx.io_context() != nullptr);
    }

    SECTION("execute_loop") {
        boost::asio::executor_work_guard work = boost::asio::make_work_guard(*ctx.io_context());
        std::atomic_bool context_thread_failed{false};
        std::thread context_thread{[&]() {
            try {
                ctx.execute_loop();
            } catch (...) {
                context_thread_failed = true;
            }
        }};
        ctx.stop();
        context_thread.join();
        CHECK(!context_thread_failed);
    }

    SECTION("stop") {
        boost::asio::executor_work_guard work = boost::asio::make_work_guard(*ctx.io_context());
        std::thread context_thread{[&]() { ctx.execute_loop(); }};
        CHECK(!ctx.io_context()->stopped());
        ctx.stop();
        CHECK(ctx.io_context()->stopped());
        context_thread.join();
        ctx.stop();
        CHECK(ctx.io_context()->stopped());
    }

    SECTION("print") {
        CHECK_NOTHROW(test_util::null_stream() << ctx);
    }
}

TEST_CASE("ContextPool", "[silkworm][concurrency][Context]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};

    SECTION("ContextPool OK") {
        ContextPool context_pool{2};
        CHECK(context_pool.num_contexts() == 0);
    }

    SECTION("ContextPool KO") {
        CHECK_THROWS_AS(ContextPool{0}, std::logic_error);
    }

    SECTION("add_context") {
        ContextPool context_pool{2};
        REQUIRE(context_pool.num_contexts() == 0);
        context_pool.add_context(Context{0, WaitMode::blocking});
        context_pool.add_context(Context{1, WaitMode::blocking});
        CHECK(context_pool.num_contexts() == 2);
    }

    SECTION("next_context") {
        ContextPool context_pool{2};
        REQUIRE(context_pool.num_contexts() == 0);
        context_pool.add_context(Context{0, WaitMode::blocking});
        context_pool.add_context(Context{1, WaitMode::blocking});
        CHECK(context_pool.num_contexts() == 2);
        auto& context1 = context_pool.next_context();
        CHECK(context1.io_context() != nullptr);
        auto& context2 = context_pool.next_context();
        CHECK(context2.io_context() != nullptr);
    }

    SECTION("next_io_context") {
        ContextPool context_pool{2};
        REQUIRE(context_pool.num_contexts() == 0);
        context_pool.add_context(Context{0, WaitMode::blocking});
        context_pool.add_context(Context{1, WaitMode::blocking});
        CHECK(context_pool.num_contexts() == 2);
        auto& context1 = context_pool.next_context();
        auto& context2 = context_pool.next_context();
        CHECK(&context_pool.next_io_context() == context1.io_context());
        CHECK(&context_pool.next_io_context() == context2.io_context());
    }

    SECTION("start/stop w/o contexts") {
        ContextPool context_pool{2};
        REQUIRE(context_pool.num_contexts() == 0);
        CHECK_NOTHROW(context_pool.start());
        CHECK_NOTHROW(context_pool.stop());
    }

    SECTION("start/stop w/ contexts") {
        ContextPool context_pool{2};
        context_pool.add_context(Context{0, WaitMode::blocking});
        context_pool.add_context(Context{1, WaitMode::blocking});
        CHECK_NOTHROW(context_pool.start());
        CHECK_NOTHROW(context_pool.stop());
    }

    SECTION("join") {
        ContextPool context_pool{2};
        context_pool.add_context(Context{0, WaitMode::blocking});
        context_pool.add_context(Context{1, WaitMode::blocking});
        context_pool.start();
        std::thread joining_thread{[&]() { context_pool.join(); }};
        context_pool.stop();
        CHECK_NOTHROW(joining_thread.join());
    }

    SECTION("join after stop") {
        ContextPool context_pool{2};
        context_pool.add_context(Context{0, WaitMode::blocking});
        context_pool.add_context(Context{1, WaitMode::blocking});
        context_pool.start();
        context_pool.stop();
        CHECK_NOTHROW(context_pool.join());
    }

    SECTION("start/stop/join w/ task enqueued") {
        ContextPool context_pool{2};
        context_pool.add_context(Context{0, WaitMode::blocking});
        context_pool.add_context(Context{1, WaitMode::blocking});
        concurrency::spawn_future(context_pool.any_executor(), [&]() -> Task<void> {
            co_await sleep(std::chrono::milliseconds(1'000));
        });
        context_pool.start();
        context_pool.stop();
        CHECK_NOTHROW(context_pool.join());
    }

    SECTION("start/destroy w/ task enqueued") {
        ContextPool context_pool{2};
        context_pool.add_context(Context{0, WaitMode::blocking});
        context_pool.add_context(Context{1, WaitMode::blocking});
        concurrency::spawn_future(context_pool.any_executor(), [&]() -> Task<void> {
            co_await sleep(std::chrono::milliseconds(1'000));
        });
        context_pool.start();
    }

    SECTION("stop/start w/o contexts") {
        ContextPool context_pool{2};
        REQUIRE(context_pool.num_contexts() == 0);
        CHECK_NOTHROW(context_pool.stop());
        CHECK_NOTHROW(context_pool.start());
    }

    SECTION("stop/start w/ contexts") {
        ContextPool context_pool{2};
        context_pool.add_context(Context{0, WaitMode::blocking});
        context_pool.add_context(Context{1, WaitMode::blocking});
        CHECK_NOTHROW(context_pool.stop());
        CHECK_NOTHROW(context_pool.start());
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::concurrency
