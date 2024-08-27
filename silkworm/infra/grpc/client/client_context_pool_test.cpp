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

#include "client_context_pool.hpp"

#include <atomic>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <string>
#include <thread>

#include <boost/asio/post.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>

#include <silkworm/infra/concurrency/sleep.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>
#include <silkworm/infra/grpc/client/call.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>

namespace silkworm::rpc {

using Catch::Matchers::Message;

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
#ifndef SILKWORM_SANITIZE

TEST_CASE("ClientContext", "[silkworm][infra][grpc][client][client_context]") {
    concurrency::WaitMode all_wait_modes[] = {
        concurrency::WaitMode::backoff,
        concurrency::WaitMode::blocking,
        concurrency::WaitMode::sleeping,
        concurrency::WaitMode::yielding,
        concurrency::WaitMode::busy_spin};
    for (auto wait_mode : all_wait_modes) {
        ClientContext context{0, wait_mode};

        SECTION(std::string("Context::Context wait_mode=") + std::to_string(static_cast<int>(wait_mode))) {
            CHECK_NOTHROW(context.io_context() != nullptr);
            CHECK_NOTHROW(context.grpc_context() != nullptr);
        }

        SECTION(std::string("Context::execute_loop wait_mode=") + std::to_string(static_cast<int>(wait_mode))) {
            std::atomic_bool processed{false};
            auto* io_context = context.io_context();
            boost::asio::post(*io_context, [&]() {
                processed = true;
                context.stop();
            });
            auto context_thread = std::thread([&]() { context.execute_loop(); });
            CHECK_NOTHROW(context_thread.join());
            CHECK(processed);
        }

        SECTION(std::string("Context::stop wait_mode=") + std::to_string(static_cast<int>(wait_mode))) {
            std::atomic_bool processed{false};
            auto* io_context = context.io_context();
            boost::asio::post(*io_context, [&]() {
                processed = true;
            });
            auto context_thread = std::thread([&]() { context.execute_loop(); });
            CHECK_NOTHROW(context.stop());
            CHECK_NOTHROW(context_thread.join());
        }

        SECTION("print") {
            CHECK_NOTHROW(test_util::null_stream() << context);
        }
    }
}

TEST_CASE("ClientContextPool: create context pool", "[silkworm][infra][grpc][client][client_context]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};

    SECTION("reject size 0") {
        CHECK_THROWS_MATCHES((ClientContextPool{0}), std::logic_error,
                             Message("ContextPool::ContextPool pool_size is 0"));
    }

    SECTION("accept size 1") {
        ClientContextPool cp{1};
        CHECK(&cp.next_context() == &cp.next_context());
        CHECK(&cp.next_io_context() == &cp.next_io_context());
    }

    SECTION("accept size greater than 1") {
        ClientContextPool cp{3};

        const auto& context1 = cp.next_context();
        const auto& context2 = cp.next_context();
        const auto& context3 = cp.next_context();

        const auto& context4 = cp.next_context();
        const auto& context5 = cp.next_context();
        const auto& context6 = cp.next_context();

        CHECK(&context1 == &context4);
        CHECK(&context2 == &context5);
        CHECK(&context3 == &context6);

        const auto& io_context1 = cp.next_io_context();
        const auto& io_context2 = cp.next_io_context();
        const auto& io_context3 = cp.next_io_context();

        const auto& io_context4 = cp.next_io_context();
        const auto& io_context5 = cp.next_io_context();
        const auto& io_context6 = cp.next_io_context();

        CHECK(&io_context1 == &io_context4);
        CHECK(&io_context2 == &io_context5);
        CHECK(&io_context3 == &io_context6);
    }
}

TEST_CASE("ClientContextPool: start context pool", "[silkworm][infra][grpc][client][client_context]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};

    SECTION("running 1 thread") {
        ClientContextPool cp{1};
        cp.start();
        cp.stop();
        cp.join();
    }

    SECTION("running 3 thread") {
        ClientContextPool cp{3};
        cp.start();
        cp.stop();
        cp.join();
    }
}

TEST_CASE("ClientContextPool: run context pool", "[silkworm][infra][grpc][client][client_context]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};

    SECTION("running 1 thread") {
        ClientContextPool cp{1};
        auto context_pool_thread = std::thread([&]() { cp.run(); });
        boost::asio::post(cp.next_io_context(), [&]() { cp.stop(); });
        CHECK_NOTHROW(context_pool_thread.join());
    }

    SECTION("running 3 thread") {
        ClientContextPool cp{3};
        auto context_pool_thread = std::thread([&]() { cp.run(); });
        boost::asio::post(cp.next_io_context(), [&]() { cp.stop(); });
        CHECK_NOTHROW(context_pool_thread.join());
    }

    SECTION("multiple runners require multiple pools") {
        ClientContextPool cp1{3};
        ClientContextPool cp2{3};
        auto context_pool_thread1 = std::thread([&]() { cp1.run(); });
        auto context_pool_thread2 = std::thread([&]() { cp2.run(); });
        boost::asio::post(cp1.next_io_context(), [&]() { cp1.stop(); });
        boost::asio::post(cp2.next_io_context(), [&]() { cp2.stop(); });
        CHECK_NOTHROW(context_pool_thread1.join());
        CHECK_NOTHROW(context_pool_thread2.join());
    }
}

TEST_CASE("ClientContextPool: stop context pool", "[silkworm][infra][grpc][client][client_context]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};

    SECTION("not yet running") {
        ClientContextPool cp{3};
        CHECK_NOTHROW(cp.stop());
    }

    SECTION("already stopped") {
        ClientContextPool cp{3};
        cp.start();
        cp.stop();
        CHECK_NOTHROW(cp.stop());
        cp.join();
    }

    SECTION("already stopped after run in dedicated thread") {
        ClientContextPool cp{3};
        auto context_pool_thread = std::thread([&]() { cp.run(); });
        boost::asio::post(cp.next_io_context(), [&]() { cp.stop(); });
        boost::asio::post(cp.next_io_context(), [&]() { cp.stop(); });
        context_pool_thread.join();
        boost::asio::post(cp.next_io_context(), [&]() { cp.stop(); });
    }
}

TEST_CASE("ClientContextPool: cannot restart context pool", "[silkworm][infra][grpc][client][client_context]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};

    SECTION("running 1 thread") {
        ClientContextPool cp{1};
        cp.start();
        cp.stop();
        cp.join();
        CHECK_THROWS_AS(cp.start(), std::logic_error);
    }

    SECTION("running 3 thread") {
        ClientContextPool cp{3};
        auto context_pool_thread = std::thread([&]() { cp.run(); });
        boost::asio::post(cp.next_io_context(), [&]() { cp.stop(); });
        CHECK_NOTHROW(context_pool_thread.join());
        CHECK_THROWS_AS(cp.start(), std::logic_error);
    }
}

TEST_CASE("ClientContextPool: handle loop exception", "[silkworm][infra][grpc][client][client_context]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};

    ClientContextPool cp{3};
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

TEST_CASE("ClientContextPool: start/stop/join w/ tasks enqueued") {
    using StubInterface = ::remote::KV::StubInterface;
    auto channel = ::grpc::CreateChannel("localhost:9090", grpc::InsecureChannelCredentials());
    std::unique_ptr<StubInterface> stub = ::remote::KV::NewStub(channel);
    ClientContextPool context_pool{5};
    SECTION("no dispatch interleaving: i-th GrpcContext notifies i-th asio::io_context") {
        for (size_t i{0}; i < context_pool.num_contexts(); ++i) {
            const auto& context = context_pool.next_context();
            concurrency::spawn_future(*context.io_context(), [&]() -> Task<void> {
                co_await unary_rpc(&StubInterface::AsyncVersion, *stub, ::google::protobuf::Empty{}, *context.grpc_context());
            });
        }
    }
    SECTION("dispatch interleaving: (i+1)-th GrpcContext notifies i-th asio::io_context") {
        // Check that dispatching calls from i-th agrpc::GrpcContext to j-th boost::asio::io_context w/ i != j works
        // This test executed in tight loop of 10'000 iterations triggered a segmentation fault in ~ClientContextPool
        // https://github.com/boostorg/asio/blob/boost-1.83.0/include/boost/asio/detail/impl/scheduler.ipp#L373
        for (size_t i{0}; i < context_pool.num_contexts(); ++i) {
            concurrency::spawn_future(context_pool.any_executor(), [&]() -> Task<void> {
                auto& grpc_context = context_pool.any_grpc_context();
                co_await unary_rpc(&StubInterface::AsyncVersion, *stub, ::google::protobuf::Empty{}, grpc_context);
            });
        }
    }
    context_pool.start();
    context_pool.stop();
    CHECK_NOTHROW(context_pool.join());
}

TEST_CASE("ClientContextPool: start/destroy w/ tasks enqueued") {
    using StubInterface = ::remote::KV::StubInterface;
    auto channel = ::grpc::CreateChannel("localhost:9090", grpc::InsecureChannelCredentials());
    std::unique_ptr<StubInterface> stub = ::remote::KV::NewStub(channel);
    ClientContextPool context_pool{5};
    SECTION("no dispatch interleaving: i-th GrpcContext notifies i-th asio::io_context") {
        for (size_t i{0}; i < context_pool.num_contexts(); ++i) {
            const auto& context = context_pool.next_context();
            concurrency::spawn_future(*context.io_context(), [&]() -> Task<void> {
                co_await unary_rpc(&StubInterface::AsyncVersion, *stub, ::google::protobuf::Empty{}, *context.grpc_context());
            });
        }
    }
    SECTION("dispatch interleaving: (i+1)-th GrpcContext notifies i-th asio::io_context") {
        // Check that dispatching calls from i-th agrpc::GrpcContext to j-th boost::asio::io_context w/ i != j works
        // This test executed in tight loop of 10'000 iterations triggered a segmentation fault in ~ClientContextPool
        // https://github.com/boostorg/asio/blob/boost-1.83.0/include/boost/asio/detail/impl/scheduler.ipp#L373
        for (size_t i{0}; i < context_pool.num_contexts(); ++i) {
            concurrency::spawn_future(context_pool.any_executor(), [&]() -> Task<void> {
                auto& grpc_context = context_pool.any_grpc_context();
                co_await unary_rpc(&StubInterface::AsyncVersion, *stub, ::google::protobuf::Empty{}, grpc_context);
            });
        }
    }
    context_pool.start();
    // We do not call ClientContextPool::stop and ClientContextPool::join explicitly here, which is a valid API usage
    // ~ClientContextPool must call them in order to allow this scenario (they're idempotent methods)
}

#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc
