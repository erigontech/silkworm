// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
    Context ctx{0};

    SECTION("ServerContext") {
        CHECK(ctx.ioc() != nullptr);
    }

    SECTION("execute_loop") {
        boost::asio::executor_work_guard work = boost::asio::make_work_guard(*ctx.ioc());
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
        boost::asio::executor_work_guard work = boost::asio::make_work_guard(*ctx.ioc());
        std::thread context_thread{[&]() { ctx.execute_loop(); }};
        CHECK(!ctx.ioc()->stopped());
        ctx.stop();
        CHECK(ctx.ioc()->stopped());
        context_thread.join();
        ctx.stop();
        CHECK(ctx.ioc()->stopped());
    }

    SECTION("print") {
        CHECK_NOTHROW(test_util::null_stream() << ctx);
    }
}

TEST_CASE("ContextPool", "[silkworm][concurrency][Context]") {
    SECTION("ContextPool OK") {
        ContextPool context_pool{2};
        CHECK(context_pool.size() == 2);
    }

    SECTION("ContextPool KO") {
        CHECK_THROWS_AS(ContextPool{0}, std::logic_error);
    }

    SECTION("next_context") {
        ContextPool context_pool{2};
        auto& context1 = context_pool.next_context();
        CHECK(context1.ioc() != nullptr);
        auto& context2 = context_pool.next_context();
        CHECK(context2.ioc() != nullptr);
    }

    SECTION("next_ioc") {
        ContextPool context_pool{2};
        auto& context1 = context_pool.next_context();
        auto& context2 = context_pool.next_context();
        CHECK(&context_pool.next_ioc() == context1.ioc());
        CHECK(&context_pool.next_ioc() == context2.ioc());
    }

    SECTION("start/stop w/ contexts") {
        ContextPool context_pool{2};
        CHECK_NOTHROW(context_pool.start());
        CHECK_NOTHROW(context_pool.stop());
    }

    SECTION("join") {
        ContextPool context_pool{2};
        context_pool.start();
        std::thread joining_thread{[&]() { context_pool.join(); }};
        context_pool.stop();
        CHECK_NOTHROW(joining_thread.join());
    }

    SECTION("join after stop") {
        ContextPool context_pool{2};
        context_pool.start();
        context_pool.stop();
        CHECK_NOTHROW(context_pool.join());
    }

    SECTION("start/stop/join w/ task enqueued") {
        ContextPool context_pool{2};
        concurrency::spawn_future(context_pool.any_executor(), [&]() -> Task<void> {
            co_await sleep(std::chrono::milliseconds(1'000));
        });
        context_pool.start();
        context_pool.stop();
        CHECK_NOTHROW(context_pool.join());
    }

    SECTION("start/destroy w/ task enqueued") {
        ContextPool context_pool{2};
        concurrency::spawn_future(context_pool.any_executor(), [&]() -> Task<void> {
            co_await sleep(std::chrono::milliseconds(1'000));
        });
        context_pool.start();
    }

    SECTION("stop/start w/ contexts") {
        ContextPool context_pool{2};
        CHECK_NOTHROW(context_pool.stop());
        CHECK_NOTHROW(context_pool.start());
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::concurrency
