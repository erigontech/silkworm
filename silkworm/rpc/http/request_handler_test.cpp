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

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#if !defined(__clang__)
#include <boost/asio/use_future.hpp>
#endif  // !defined(__clang__)

#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/rpc/commands/rpc_api_table.hpp>
#include <silkworm/rpc/common/constants.hpp>


#include <catch2/catch.hpp>

namespace silkworm::rpc::http {

//! Represents a single connection from a client.
class HandlerListener : public Channel {
public:
    Task<void> write_rsp(Response& response) override {
       response_ = response;
       co_return;
    }

    Task<void> open_stream() override {
       co_return;
    }

    Task<std::size_t> write(std::string_view /* content */) override {
       co_return 0;
    }

    Task<void> close() override {
       co_return;
    }

    Response& get_response () {return response_; }

private:
    Response response_;
};


TEST_CASE("check handle_request no method", "[rpc][handle]") {
        boost::asio::thread_pool workers{1};
        ClientContextPool cp{1};
        add_shared_service(cp.next_io_context(), std::make_shared<BlockCache>());
        add_shared_service<ethdb::kv::StateCache>(cp.next_io_context(), std::make_shared<ethdb::kv::CoherentStateCache>());

        cp.start();
        HandlerListener listener;
        commands::RpcApi api{cp.next_io_context(), workers};
        commands::RpcApiTable handler_table{kDefaultEth1ApiSpec};
        const std::string json = {"{\"jsonrpc\":\"2.0\",\"id\":3 }"};
        RequestHandler h{&listener, api, handler_table};
        cp.start();

        try {
            auto result{boost::asio::co_spawn(cp.next_io_context(), h.handle(json), boost::asio::use_future)};
            result.get();
        } catch (...) {
           std::cout << "exception\n";
           CHECK(false);
        }

        CHECK(listener.get_response().content == "");
        CHECK(listener.get_response().status == Channel::ResponseStatus::no_content);
        cp.stop();
        cp.join();
}

TEST_CASE("check handle_request invalid method", "[rpc][handle_request]") {
        boost::asio::io_context io_context;
        std::thread io_context_thread{[&io_context]() { io_context.run(); }};

        boost::asio::thread_pool workers{1};
        ClientContextPool cp{1};
        cp.start();

        HandlerListener listener;
        commands::RpcApi api{cp.next_io_context(), workers};
        commands::RpcApiTable handler_table{kDefaultEth1ApiSpec};
        const std::string json = {"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"eth_AAA\"}"};

        try {
            RequestHandler h{&listener, api, handler_table};
            auto result{boost::asio::co_spawn(cp.next_io_context(), h.handle(json), boost::asio::use_future)};
            result.get();
        } catch (...) {
           CHECK(false);
        }

        CHECK(listener.get_response().content == "");
        CHECK(listener.get_response().status == Channel::ResponseStatus::not_implemented);
        cp.stop();
        cp.join();
}

TEST_CASE("check handle_request method return failed", "[rpc][handle_request]") {
        boost::asio::io_context io_context;
        std::thread io_context_thread{[&io_context]() { io_context.run(); }};

        boost::asio::thread_pool workers{1};
        ClientContextPool cp{1};
        cp.start();

        HandlerListener listener;
        commands::RpcApi api{cp.next_io_context(), workers};
        commands::RpcApiTable handler_table{kDefaultEth1ApiSpec};
        const std::string json = {"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"eth_getBlockByNumber\",\"params\":[]}"};

        try {
            RequestHandler h{&listener, api, handler_table};
            auto result{boost::asio::co_spawn(cp.next_io_context(), h.handle(json), boost::asio::use_future)};
            result.get();
        } catch (...) {
           CHECK(false);
        }

        CHECK(listener.get_response().content == "");
        CHECK(listener.get_response().status == Channel::ResponseStatus::ok);
        cp.stop();
        cp.join();
}

}  // namespace silkworm::rpc::http
