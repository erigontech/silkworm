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
#include <memory>
#include <thread>

#include <catch2/catch.hpp>
#include <grpc/grpc.h>

#include <silkworm/common/base.hpp>
#include <silkworm/common/log.hpp>

// Factory function creating one null output stream (all characters are discarded)
inline std::ostream& null_stream() {
    static struct null_buf : public std::streambuf {
        int overflow(int c) override { return c; }
    } null_buf;
    static struct null_strm : public std::ostream {
        null_strm() : std::ostream(&null_buf) {}
    } null_strm;
    return null_strm;
}

namespace silkworm::rpc {

TEST_CASE("ServerContext", "[silkworm][rpc][server_context]") {
    grpc::ServerBuilder builder;
    std::unique_ptr<grpc::ServerCompletionQueue> scq = builder.AddCompletionQueue();
    grpc::ServerCompletionQueue* scq_ptr = scq.get();
    ServerContext server_context{std::move(scq)};

    SECTION("ServerContext") {
        CHECK(server_context.server_queue() == scq_ptr);
        CHECK(server_context.client_queue() != nullptr);
        CHECK(server_context.server_end_point() != nullptr);
        CHECK(server_context.client_end_point() != nullptr);
    }

    SECTION("execution_loop") {
        boost::asio::io_context::work work{*server_context.io_context()};
        std::atomic_bool context_thread_failed{false};
        std::thread context_thread{[&]() {
            try {
                server_context.execution_loop();
            } catch (...) {
                context_thread_failed = true;
            }
        }};
        server_context.stop();
        context_thread.join();
        CHECK(!context_thread_failed);
    }

    SECTION("stop") {
        boost::asio::io_context::work work{*server_context.io_context()};
        std::thread context_thread{[&]() { server_context.execution_loop(); }};
        CHECK(!server_context.io_context()->stopped());
        server_context.stop();
        CHECK(server_context.io_context()->stopped());
        context_thread.join();
        server_context.stop();
        CHECK(server_context.io_context()->stopped());
    }

    SECTION("print") {
        silkworm::log::set_verbosity(silkworm::log::Level::kNone);
        CHECK_NOTHROW(null_stream() << server_context);
    }
}

} // namespace silkworm::rpc
