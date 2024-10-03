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

#include "server_context_pool.hpp"

#include <atomic>
#include <stdexcept>
#include <thread>

#include <boost/asio/executor_work_guard.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/test_util/null_stream.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc {

using namespace concurrency;

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
#ifndef SILKWORM_SANITIZE
TEST_CASE("ServerContext", "[silkworm][infra][grpc][server][server_context]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    grpc::ServerBuilder builder;
    std::unique_ptr<grpc::ServerCompletionQueue> scq = builder.AddCompletionQueue();
    grpc::ServerCompletionQueue* scq_ptr = scq.get();
    ServerContext server_context{0, std::move(scq)};

    SECTION("ServerContext") {
        CHECK(server_context.server_grpc_context() != nullptr);
        CHECK(server_context.client_grpc_context() != nullptr);
        CHECK(server_context.io_context() != nullptr);
        CHECK(server_context.server_grpc_context()->get_completion_queue() == scq_ptr);
        CHECK(server_context.client_grpc_context()->get_completion_queue() != nullptr);
    }

    SECTION("execute_loop") {
        boost::asio::executor_work_guard work = boost::asio::make_work_guard(*server_context.io_context());
        std::atomic_bool context_thread_failed{false};
        std::thread context_thread{[&]() {
            try {
                server_context.execute_loop();
            } catch (...) {
                context_thread_failed = true;
            }
        }};
        server_context.stop();
        context_thread.join();
        CHECK(!context_thread_failed);
    }

    SECTION("stop") {
        boost::asio::executor_work_guard work = boost::asio::make_work_guard(*server_context.io_context());
        std::thread context_thread{[&]() { server_context.execute_loop(); }};
        CHECK(!server_context.io_context()->stopped());
        server_context.stop();
        CHECK(server_context.io_context()->stopped());
        context_thread.join();
        server_context.stop();
        CHECK(server_context.io_context()->stopped());
    }

    SECTION("print") {
        CHECK_NOTHROW(test_util::null_stream() << server_context);
    }
}

TEST_CASE("ServerContextPool", "[silkworm][infra][grpc][server][server_context]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    grpc::ServerBuilder builder;

    SECTION("ServerContextPool OK") {
        ServerContextPool server_context_pool{{2}, builder};
        CHECK(server_context_pool.size() == 2);
    }

    SECTION("ServerContextPool KO") {
        CHECK_THROWS_AS((ServerContextPool{concurrency::ContextPoolSettings{0}, builder}), std::logic_error);
    }

    SECTION("next_context") {
        ServerContextPool server_context_pool{{2}, builder};
        auto& context1 = server_context_pool.next_context();
        auto& context2 = server_context_pool.next_context();
        CHECK(&server_context_pool.next_context() == &context1);
        CHECK(&server_context_pool.next_context() == &context2);
    }

    SECTION("next_io_context") {
        ServerContextPool server_context_pool{{2}, builder};
        auto& context1 = server_context_pool.next_context();
        CHECK(context1.io_context() != nullptr);
        auto& context2 = server_context_pool.next_context();
        CHECK(context2.io_context() != nullptr);
        CHECK(&server_context_pool.next_io_context() == context1.io_context());
        CHECK(&server_context_pool.next_io_context() == context2.io_context());
    }

    SECTION("start/stop w/ contexts") {
        ServerContextPool server_context_pool{{2}, builder};
        CHECK_NOTHROW(server_context_pool.start());
        CHECK_NOTHROW(server_context_pool.stop());
    }

    SECTION("join") {
        ServerContextPool server_context_pool{{2}, builder};
        server_context_pool.start();
        std::thread joining_thread{[&]() { server_context_pool.join(); }};
        server_context_pool.stop();
        CHECK_NOTHROW(joining_thread.join());
    }

    SECTION("join after stop") {
        ServerContextPool server_context_pool{{2}, builder};
        server_context_pool.start();
        server_context_pool.stop();
        CHECK_NOTHROW(server_context_pool.join());
    }
}

TEST_CASE("ServerContextPool: handle loop exception", "[silkworm][infra][grpc][client][client_context]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    grpc::ServerBuilder builder;

    ServerContextPool cp{{3}, builder};
    std::exception_ptr run_exception;
    cp.set_exception_handler([&](std::exception_ptr eptr) {  // NOLINT(performance-unnecessary-value-param)
        run_exception = eptr;
        // In case of any loop exception in any thread, close down the pool
        cp.stop();
    });
    auto context_pool_thread = std::thread([&]() { cp.run(); });
    boost::asio::post(cp.next_io_context(), [&]() { throw std::logic_error{"unexpected"}; });
    CHECK_NOTHROW(context_pool_thread.join());
    CHECK(bool(run_exception));
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc
