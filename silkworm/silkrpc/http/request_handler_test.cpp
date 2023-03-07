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

#include "request_handler.hpp"

#include <memory>
#include <thread>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch.hpp>
#include <silkworm/core/common/util.hpp>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/concurrency/context_pool.hpp>
#include <silkworm/silkrpc/http/request.hpp>
#include <silkworm/silkrpc/http/reply.hpp>
#include <silkworm/silkrpc/http/header.hpp>

namespace silkrpc::http {

using Catch::Matchers::Message;

TEST_CASE("check handle_request  empty content ", "[silkrpc][handle_request]") {
    silkrpc::http::Request req {
        "eth_call",
        "",
        1,
        3,
        {{"v", "1"}},
        0,
        ""
    };
    silkrpc::http::Reply reply {};

/*
    ContextPool cp{1, []() { return grpc::CreateChannel("localhost", grpc::InsecureChannelCredentials()); }};
    auto context_pool_thread = std::thread([&]() { cp.run(); });
    boost::asio::thread_pool workers{1};
    try {
        silkrpc::http::RequestHandler h{cp.next_context(), workers};
        auto result{boost::asio::co_spawn(cp.next_io_context(), h.handle_request(req, reply), boost::asio::use_future)};
        result.get();
    } catch (...) {
       CHECK(false);
    }

    CHECK(reply.content == "");
    CHECK(reply.status == 204);
    CHECK(reply.headers.size() == 2);
    CHECK(reply.headers[0].name == "Content-Length");
    CHECK(reply.headers[0].value == "0");
    CHECK(reply.headers[1].name == "Content-Type");
    CHECK(reply.headers[1].value == "application/json");
    cp.stop();
    context_pool_thread.join();
*/
}

TEST_CASE("check handle_request no method", "[silkrpc][handle_request]") {
    silkrpc::http::Request req {
        "eth_call",
        "",
        1,
        3,
        {{"v", "1"}},
        24,
        "{\"jsonrpc\":\"2.0\",\"id\":3 }"
    };
    silkrpc::http::Reply reply {};

/*
    ContextPool cp{1, []() { return grpc::CreateChannel("localhost", grpc::InsecureChannelCredentials()); }};
    auto context_pool_thread = std::thread([&]() { cp.run(); });
    boost::asio::thread_pool workers{1};

    try {
        silkrpc::http::RequestHandler h{cp.next_context(), workers};
        auto result{boost::asio::co_spawn(cp.next_io_context(), h.handle_request(req, reply), boost::asio::use_future)};
        result.get();
    } catch (...) {
       CHECK(false);
    }
    CHECK(reply.content == "{\"error\":{\"code\":-32600,\"message\":\"method missing\"},\"id\":3,\"jsonrpc\":\"2.0\"}\n");
    CHECK(reply.status == 400);
    CHECK(reply.headers.size() == 2);
    CHECK(reply.headers[0].name == "Content-Length");
    CHECK(reply.headers[0].value == "76");
    CHECK(reply.headers[1].name == "Content-Type");
    CHECK(reply.headers[1].value == "application/json");
    cp.stop();
    context_pool_thread.join();
*/
}

TEST_CASE("check handle_request invalid method", "[silkrpc][handle_request]") {
    silkrpc::http::Request req {
        "eth_call",
        "",
        1,
        3,
        {{"v", "1"}},
        24,
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"eth_AAA\"}"
    };
    silkrpc::http::Reply reply {};

/*
    ContextPool cp{1, []() { return grpc::CreateChannel("localhost", grpc::InsecureChannelCredentials()); }};
    auto context_pool_thread = std::thread([&]() { cp.run(); });
    boost::asio::thread_pool workers{1};

    try {
        silkrpc::http::RequestHandler h{cp.next_context(), workers};
        auto result{boost::asio::co_spawn(cp.next_io_context(), h.handle_request(req, reply), boost::asio::use_future)};
        result.get();
    } catch (...) {
       CHECK(false);
    }
    CHECK(reply.content == "{\"error\":{\"code\":-32601,\"message\":\"method not existent or not implemented\"},\"id\":3,\"jsonrpc\":\"2.0\"}\n");
    CHECK(reply.status == 501);
    CHECK(reply.headers.size() == 2);
    CHECK(reply.headers[0].name == "Content-Length");
    CHECK(reply.headers[0].value == "100");
    CHECK(reply.headers[1].name == "Content-Type");
    CHECK(reply.headers[1].value == "application/json");
    cp.stop();
    context_pool_thread.join();
*/
}

TEST_CASE("check handle_request method return failed", "[silkrpc][handle_request]") {
    silkrpc::http::Request req {
        "eth_call",
        "",
        1,
        3,
        {{"v", "1"}},
        70,
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"eth_getBlockByNumber\",\"params\":[]}"
    };
    silkrpc::http::Reply reply {};

/*
    ContextPool cp{1, []() { return grpc::CreateChannel("localhost", grpc::InsecureChannelCredentials()); }};
    auto context_pool_thread = std::thread([&]() { cp.run(); });
    boost::asio::thread_pool workers{1};

    silkrpc::http::RequestHandler h{cp.next_context(), workers};
    try {
        silkrpc::http::RequestHandler h{cp.next_context(), workers};
        auto result{boost::asio::co_spawn(cp.next_io_context(), h.handle_request(req, reply), boost::asio::use_future)};
        result.get();
    } catch (...) {
       CHECK(false);
    }
    CHECK(reply.content == "{\"error\":{\"code\":100,\"message\":\"invalid getBlockByNumber params: []\"},\"id\":3,\"jsonrpc\":\"2.0\"}\n");
    CHECK(reply.status == 200);
    CHECK(reply.headers.size() == 2);
    CHECK(reply.headers[0].name == "Content-Length");
    CHECK(reply.headers[0].value == "94");
    CHECK(reply.headers[1].name == "Content-Type");
    CHECK(reply.headers[1].value == "application/json");
    cp.stop();
    context_pool_thread.join();
*/
}

} // namespace silkrpc::http

