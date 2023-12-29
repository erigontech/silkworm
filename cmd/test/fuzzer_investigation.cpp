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

#include <boost/asio/async_result.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_future.hpp>
#include <nlohmann/json.hpp>

class RequestHandler_ForTest {
  public:
    boost::asio::awaitable<void> handle_request(const std::string& request_str) {
        try {
            co_await is_valid_json(request_str);
        } catch (const std::invalid_argument& e) {
            std::cerr << "Invalid argument: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "Error occurred" << std::endl;
        }
    }

    boost::asio::awaitable<bool> is_valid_json(const std::string& request_str) {
        if (request_str.length() == 20) {
            std::cout << "Target length found, terminating, request_str: " << request_str << std::endl;
            throw std::invalid_argument("Invalid argument");
        }

        co_return nlohmann::json::accept(request_str);
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    auto request_str = std::string(reinterpret_cast<const char*>(Data), Size);

    try {
        auto io_context = boost::asio::io_context{};
        auto result = boost::asio::co_spawn(
            io_context, [&request_str]() -> boost::asio::awaitable<void> {
                try {
                    RequestHandler_ForTest handler{};
                    co_await handler.handle_request(request_str);
                } catch (const std::exception& e) {
                    std::cerr << e.what() << '\n';
                }
            },
            boost::asio::use_future);

        io_context.run();

        result.get();

        io_context.restart();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    } catch (...) {
        std::cout << "Error" << std::endl;
    }

    return 0;
}
