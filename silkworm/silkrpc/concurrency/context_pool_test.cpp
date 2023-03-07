/*
   Copyright 2021 The Silkrpc Authors

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
#include <string>
#include <thread>

#include <boost/asio/post.hpp>
#include <catch2/catch.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/node/common/log.hpp>

namespace silkrpc {

using Catch::Matchers::Message;

ChannelFactory create_channel = []() { return grpc::CreateChannel("localhost", grpc::InsecureChannelCredentials()); };

TEST_CASE("Context", "[silkrpc][context_pool]") {
    SILKRPC_LOG_VERBOSITY(LogLevel::None);

    auto block_cache = std::make_shared<BlockCache>();
    auto state_cache = std::make_shared<ethdb::kv::CoherentStateCache>();

    WaitMode all_wait_modes[] = {
        WaitMode::backoff, WaitMode::blocking, WaitMode::sleeping, WaitMode::yielding, WaitMode::spin_wait, WaitMode::busy_spin
    };
    for (auto wait_mode : all_wait_modes) {
        SECTION(std::string("Context::Context wait_mode=") + std::to_string(static_cast<int>(wait_mode))) {
            Context context{create_channel, block_cache, state_cache, {}, wait_mode};
            CHECK_NOTHROW(context.io_context() != nullptr);
            CHECK_NOTHROW(context.grpc_context() != nullptr);
            CHECK_NOTHROW(context.backend() != nullptr);
            CHECK_NOTHROW(context.miner() != nullptr);
            CHECK_NOTHROW(context.block_cache() != nullptr);
        }

        SECTION(std::string("Context::execute_loop wait_mode=") + std::to_string(static_cast<int>(wait_mode))) {
            Context context{create_channel, block_cache, state_cache,  /* env */{}, wait_mode};
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
            Context context{create_channel, block_cache, state_cache, /* env */{}, wait_mode};
            std::atomic_bool processed{false};
            auto* io_context = context.io_context();
            boost::asio::post(*io_context, [&]() {
                processed = true;
            });
            auto context_thread = std::thread([&]() { context.execute_loop(); });
            CHECK_NOTHROW(context.stop());
            CHECK_NOTHROW(context_thread.join());
        }
    }
}

TEST_CASE("Context with chain_env", "[silkrpc][context_pool]") {
      std::shared_ptr<mdbx::env_managed> chain_env = std::make_shared<mdbx::env_managed>();
      auto block_cache = std::make_shared<BlockCache>();
      auto state_cache = std::make_shared<ethdb::kv::CoherentStateCache>();
      Context context{create_channel, block_cache, state_cache, chain_env};
      std::atomic_bool processed{false};
      auto* io_context = context.io_context();
      boost::asio::post(*io_context, [&]() {
         processed = true;
      });
      auto context_thread = std::thread([&]() { context.execute_loop(); });
      CHECK_NOTHROW(context.stop());
      CHECK_NOTHROW(context_thread.join());
}

TEST_CASE("create context pool", "[silkrpc][context_pool]") {
    SILKRPC_LOG_VERBOSITY(LogLevel::None);

    SECTION("reject size 0") {
        CHECK_THROWS_MATCHES((ContextPool{0, create_channel}), std::logic_error, Message("ContextPool::ContextPool pool_size is 0"));
    }

    SECTION("accept size 1") {
        ContextPool cp{1, create_channel};
        CHECK(&cp.next_context() == &cp.next_context());
        CHECK(&cp.next_io_context() == &cp.next_io_context());
    }

    SECTION("accept size greater than 1") {
        ContextPool cp{3, create_channel};

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

TEST_CASE("start context pool", "[silkrpc][context_pool]") {
    SILKRPC_LOG_VERBOSITY(LogLevel::None);

    SECTION("running 1 thread") {
        ContextPool cp{1, create_channel};
        cp.start();
        cp.stop();
        cp.join();
    }

    SECTION("running 3 thread") {
        ContextPool cp{3, create_channel};
        cp.start();
        cp.stop();
        cp.join();
    }
}

TEST_CASE("run context pool", "[silkrpc][context_pool]") {
    SILKRPC_LOG_VERBOSITY(LogLevel::None);

    SECTION("running 1 thread") {
        ContextPool cp{1, create_channel};
        auto context_pool_thread = std::thread([&]() { cp.run(); });
        boost::asio::post(cp.next_io_context(), [&]() { cp.stop(); });
        CHECK_NOTHROW(context_pool_thread.join());
    }

    SECTION("running 3 thread") {
        ContextPool cp{3, create_channel};
        auto context_pool_thread = std::thread([&]() { cp.run(); });
        boost::asio::post(cp.next_io_context(), [&]() { cp.stop(); });
        CHECK_NOTHROW(context_pool_thread.join());
    }

    SECTION("multiple runners require multiple pools") {
        ContextPool cp1{3, create_channel};
        ContextPool cp2{3, create_channel};
        auto context_pool_thread1 = std::thread([&]() { cp1.run(); });
        auto context_pool_thread2 = std::thread([&]() { cp2.run(); });
        boost::asio::post(cp1.next_io_context(), [&]() { cp1.stop(); });
        boost::asio::post(cp2.next_io_context(), [&]() { cp2.stop(); });
        CHECK_NOTHROW(context_pool_thread1.join());
        CHECK_NOTHROW(context_pool_thread2.join());
    }
}

TEST_CASE("stop context pool", "[silkrpc][context_pool]") {
    SILKRPC_LOG_VERBOSITY(LogLevel::None);

    SECTION("not yet running") {
        ContextPool cp{3, create_channel};
        CHECK_NOTHROW(cp.stop());
    }

    SECTION("already stopped") {
        ContextPool cp{3, create_channel};
        cp.start();
        cp.stop();
        CHECK_NOTHROW(cp.stop());
        cp.join();
    }

    SECTION("already stopped after run in dedicated thread") {
        ContextPool cp{3, create_channel};
        auto context_pool_thread = std::thread([&]() { cp.run(); });
        boost::asio::post(cp.next_io_context(), [&]() { cp.stop(); });
        boost::asio::post(cp.next_io_context(), [&]() { cp.stop(); });
        context_pool_thread.join();
        boost::asio::post(cp.next_io_context(), [&]() { cp.stop(); });
    }
}

TEST_CASE("cannot restart context pool", "[silkrpc][context_pool]") {
    SILKRPC_LOG_VERBOSITY(LogLevel::None);

    SECTION("running 1 thread") {
        ContextPool cp{1, create_channel};
        cp.start();
        cp.stop();
        cp.join();
        CHECK_THROWS_AS(cp.start(), std::logic_error);
    }

    SECTION("running 3 thread") {
        ContextPool cp{3, create_channel};
        auto context_pool_thread = std::thread([&]() { cp.run(); });
        boost::asio::post(cp.next_io_context(), [&]() { cp.stop(); });
        CHECK_NOTHROW(context_pool_thread.join());
        CHECK_THROWS_AS(cp.start(), std::logic_error);
    }
}

TEST_CASE("print context pool", "[silkrpc][context_pool]") {
    SILKRPC_LOG_VERBOSITY(LogLevel::None);
    ContextPool cp{1, create_channel};
    CHECK_NOTHROW(null_stream() << cp.next_context());
}

} // namespace silkrpc
