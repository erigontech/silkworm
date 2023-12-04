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

#include "request_handler.hpp"

#include <catch2/catch.hpp>

#include <silkworm/silkrpc/http/reply.hpp>
#include <silkworm/silkrpc/http/request.hpp>

namespace silkworm::rpc::http {

TEST_CASE("check handle_request  empty content ", "[silkrpc][handle_request]") {
    Request req{
        "eth_call",
        "",
        1,
        3,
        {{"v", "1"}},
        0,
        ""};
    Reply reply{};

    /*
        ContextPool cp{1, []() { return grpc::CreateChannel("localhost", grpc::InsecureChannelCredentials()); }};
        auto context_pool_thread = std::thread([&]() { cp.run(); });
        boost::asio::thread_pool workers{1};
        try {
            RequestHandler h{cp.next_context(), workers};
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
    Request req{
        "eth_call",
        "",
        1,
        3,
        {{"v", "1"}},
        24,
        R"({"jsonrpc":"2.0","id":3 })"};
    Reply reply{};

    /*
        ContextPool cp{1, []() { return grpc::CreateChannel("localhost", grpc::InsecureChannelCredentials()); }};
        auto context_pool_thread = std::thread([&]() { cp.run(); });
        boost::asio::thread_pool workers{1};

        try {
            RequestHandler h{cp.next_context(), workers};
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
    Request req{
        "eth_call",
        "",
        1,
        3,
        {{"v", "1"}},
        24,
        R"({"jsonrpc":"2.0","id":3,"method":"eth_AAA"})"};
    Reply reply{};

    /*
        ContextPool cp{1, []() { return grpc::CreateChannel("localhost", grpc::InsecureChannelCredentials()); }};
        auto context_pool_thread = std::thread([&]() { cp.run(); });
        boost::asio::thread_pool workers{1};

        try {
            RequestHandler h{cp.next_context(), workers};
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
    Request req{
        "eth_call",
        "",
        1,
        3,
        {{"v", "1"}},
        70,
        R"({"jsonrpc":"2.0","id":3,"method":"eth_getBlockByNumber","params":[]})"};
    Reply reply{};

    /*
        ContextPool cp{1, []() { return grpc::CreateChannel("localhost", grpc::InsecureChannelCredentials()); }};
        auto context_pool_thread = std::thread([&]() { cp.run(); });
        boost::asio::thread_pool workers{1};

        RequestHandler h{cp.next_context(), workers};
        try {
            RequestHandler h{cp.next_context(), workers};
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

}  // namespace silkworm::rpc::http
