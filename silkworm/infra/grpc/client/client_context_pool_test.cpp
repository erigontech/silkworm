// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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

#include <silkworm/core/test_util/null_stream.hpp>
#include <silkworm/infra/concurrency/sleep.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>
#include <silkworm/infra/grpc/client/call.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>

namespace silkworm::rpc {

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
#ifndef SILKWORM_SANITIZE

TEST_CASE("ClientContext", "[silkworm][infra][grpc][client][client_context]") {
    {
        ClientContext context{0};

        SECTION("Context::Context") {
            CHECK_NOTHROW(context.ioc() != nullptr);
            CHECK_NOTHROW(context.grpc_context() != nullptr);
        }

        SECTION("Context::execute_loop") {
            std::atomic_bool processed{false};
            auto* ioc = context.ioc();
            boost::asio::post(*ioc, [&]() {
                processed = true;
                context.stop();
            });
            auto context_thread = std::thread([&]() { context.execute_loop(); });
            CHECK_NOTHROW(context_thread.join());
            CHECK(processed);
        }

        SECTION("Context::stop") {
            std::atomic_bool processed{false};
            auto* ioc = context.ioc();
            boost::asio::post(*ioc, [&]() {
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
    SECTION("reject size 0") {
        CHECK_THROWS_AS((ClientContextPool{0}), std::logic_error);
    }

    SECTION("accept size 1") {
        ClientContextPool cp{1};
        CHECK(&cp.next_context() == &cp.next_context());
        CHECK(&cp.next_ioc() == &cp.next_ioc());
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

        const auto& ioc1 = cp.next_ioc();
        const auto& ioc2 = cp.next_ioc();
        const auto& ioc3 = cp.next_ioc();

        const auto& ioc4 = cp.next_ioc();
        const auto& ioc5 = cp.next_ioc();
        const auto& ioc6 = cp.next_ioc();

        CHECK(&ioc1 == &ioc4);
        CHECK(&ioc2 == &ioc5);
        CHECK(&ioc3 == &ioc6);
    }
}

TEST_CASE("ClientContextPool: start context pool", "[silkworm][infra][grpc][client][client_context]") {
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
    SECTION("running 1 thread") {
        ClientContextPool cp{1};
        auto context_pool_thread = std::thread([&]() { cp.run(); });
        boost::asio::post(cp.next_ioc(), [&]() { cp.stop(); });
        CHECK_NOTHROW(context_pool_thread.join());
    }

    SECTION("running 3 thread") {
        ClientContextPool cp{3};
        auto context_pool_thread = std::thread([&]() { cp.run(); });
        boost::asio::post(cp.next_ioc(), [&]() { cp.stop(); });
        CHECK_NOTHROW(context_pool_thread.join());
    }

    SECTION("multiple runners require multiple pools") {
        ClientContextPool cp1{3};
        ClientContextPool cp2{3};
        auto context_pool_thread1 = std::thread([&]() { cp1.run(); });
        auto context_pool_thread2 = std::thread([&]() { cp2.run(); });
        boost::asio::post(cp1.next_ioc(), [&]() { cp1.stop(); });
        boost::asio::post(cp2.next_ioc(), [&]() { cp2.stop(); });
        CHECK_NOTHROW(context_pool_thread1.join());
        CHECK_NOTHROW(context_pool_thread2.join());
    }
}

TEST_CASE("ClientContextPool: stop context pool", "[silkworm][infra][grpc][client][client_context]") {
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
        boost::asio::post(cp.next_ioc(), [&]() { cp.stop(); });
        boost::asio::post(cp.next_ioc(), [&]() { cp.stop(); });
        context_pool_thread.join();
        boost::asio::post(cp.next_ioc(), [&]() { cp.stop(); });
    }
}

TEST_CASE("ClientContextPool: cannot restart context pool", "[silkworm][infra][grpc][client][client_context]") {
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
        boost::asio::post(cp.next_ioc(), [&]() { cp.stop(); });
        CHECK_NOTHROW(context_pool_thread.join());
        CHECK_THROWS_AS(cp.start(), std::logic_error);
    }
}

TEST_CASE("ClientContextPool: handle loop exception", "[silkworm][infra][grpc][client][client_context]") {
    ClientContextPool cp{3};
    std::exception_ptr run_exception;
    cp.set_exception_handler([&](std::exception_ptr eptr) {
        run_exception = eptr;
        // In case of any loop exception in any thread, close down the pool
        cp.stop();
    });
    auto context_pool_thread = std::thread([&]() { cp.run(); });
    boost::asio::post(cp.next_ioc(), [&]() { throw std::logic_error{"unexpected"}; });
    CHECK_NOTHROW(context_pool_thread.join());
    CHECK(bool(run_exception));
}

TEST_CASE("ClientContextPool: start/stop/join w/ tasks enqueued") {
    using StubInterface = ::remote::KV::StubInterface;
    auto channel = ::grpc::CreateChannel("localhost:9090", grpc::InsecureChannelCredentials());
    std::unique_ptr<StubInterface> stub = ::remote::KV::NewStub(channel);
    ClientContextPool context_pool{5};
    SECTION("no dispatch interleaving: i-th GrpcContext notifies i-th asio::io_context") {
        for (size_t i = 0; i < context_pool.size(); ++i) {
            const auto& context = context_pool.next_context();
            concurrency::spawn_future(*context.ioc(), [&]() -> Task<void> {
                co_await unary_rpc(&StubInterface::AsyncVersion, *stub, ::google::protobuf::Empty{}, *context.grpc_context());
            });
        }
    }
    SECTION("dispatch interleaving: (i+1)-th GrpcContext notifies i-th asio::io_context") {
        // Check that dispatching calls from i-th agrpc::GrpcContext to j-th boost::asio::io_context w/ i != j works
        // This test executed in tight loop of 10'000 iterations triggered a segmentation fault in ~ClientContextPool
        // https://github.com/boostorg/asio/blob/boost-1.83.0/include/boost/asio/detail/impl/scheduler.ipp#L373
        for (size_t i = 0; i < context_pool.size(); ++i) {
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
        for (size_t i = 0; i < context_pool.size(); ++i) {
            const auto& context = context_pool.next_context();
            concurrency::spawn_future(*context.ioc(), [&]() -> Task<void> {
                co_await unary_rpc(&StubInterface::AsyncVersion, *stub, ::google::protobuf::Empty{}, *context.grpc_context());
            });
        }
    }
    SECTION("dispatch interleaving: (i+1)-th GrpcContext notifies i-th asio::io_context") {
        // Check that dispatching calls from i-th agrpc::GrpcContext to j-th boost::asio::io_context w/ i != j works
        // This test executed in tight loop of 10'000 iterations triggered a segmentation fault in ~ClientContextPool
        // https://github.com/boostorg/asio/blob/boost-1.83.0/include/boost/asio/detail/impl/scheduler.ipp#L373
        for (size_t i = 0; i < context_pool.size(); ++i) {
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
