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

#include <iostream>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/async_result.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_future.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/infra/grpc/client/client_context_pool.hpp>

#include "address_sanitizer_fix.hpp"

template <typename TestRequestHandler>
class RpcApiTestBase {
  public:
    explicit RpcApiTestBase() : context_{0, silkworm::concurrency::WaitMode::yielding},
                                io_context_{*context_.io_context()} {
    }
    explicit RpcApiTestBase(silkworm::rpc::ClientContext client_context) : context_{client_context},
                                                                           io_context_{*context_.io_context()} {
    }

    template <auto method, typename... Args>
    auto run(Args&&... args) {
        TestRequestHandler handler{};
        return spawn_and_wait((handler.*method)(std::forward<Args>(args)...));
    }

    template <typename AwaitableOrFunction>
    auto spawn_and_wait(AwaitableOrFunction&& awaitable) {
        return spawn(std::forward<AwaitableOrFunction>(awaitable)).get();
    }

    template <typename AwaitableOrFunction>
    auto spawn(AwaitableOrFunction&& awaitable) {
        return boost::asio::co_spawn(io_context_, std::forward<AwaitableOrFunction>(awaitable), boost::asio::use_future);
    }

    silkworm::rpc::ClientContext context_;
    boost::asio::io_context& io_context_;
};

class RequestHandler_ForTest {
  public:
    RequestHandler_ForTest() {
    }

    silkworm::Task<void> handle_request(const std::string& request_str, std::string& reply) {
        try {
            co_await handle(request_str);

            co_return;
        } catch (const std::exception& e) {
            std::cerr << e.what() << '\n';
        }
        co_return;
    }

    silkworm::Task<std::string> handle(const std::string& request_str) {
        auto is_valid = co_await is_valid_json(request_str);
        if (!is_valid) {
            co_return "invalid json";
        }

        auto request_json = nlohmann::json::parse(request_str);

        if (request_json.contains("method")) {
            auto method = request_json["method"].get<std::string>();

            if (method == "eth_getBlockByNumber") {
                co_return "found, exiting";
            }
        }

        co_return "";
    }

    silkworm::Task<bool> is_valid_json(const std::string& request_str) {
        if (request_str.length() == 20) {
            std::cout << "JG request_str: " << request_str << std::endl;
            throw std::invalid_argument("invalid json");
        }

        co_return nlohmann::json::accept(request_str);
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    auto request_str = std::string(reinterpret_cast<const char*>(Data), Size);
    auto reply = std::string();

    static silkworm::rpc::ClientContext client_context{0, silkworm::concurrency::WaitMode::yielding};

    try {
        // std::cout << "JG request_str: " << request_str << std::endl;

        auto io_context = boost::asio::io_context{};

        boost::asio::co_spawn(
            io_context, [&request_str, &reply]() -> boost::asio::awaitable<void> {
                RequestHandler_ForTest handler{};
                co_await handler.handle_request(request_str, reply);
            },
            boost::asio::detached);

        io_context.run();
    } catch (...) {
        std::cout << "JG Error" << std::endl;
        // std::exception_ptr eptr = std::current_exception();
        // try {
        //     if (eptr) {
        //         std::rethrow_exception(eptr);
        //     }
        // } catch (const std::exception& e) {
        //     std::cout << "Caught exception: " << e.what() << std::endl;
        // }
    }

    if (reply == "") {
        return 0;
    }

    return -1;
}
