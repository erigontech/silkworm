/*
    Copyright 2020 The Silkrpc Authors

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
//
// Copyright (c) 2003-2020 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <string>
#include <tuple>
#include <vector>

#include <silkworm/silkrpc/config.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>

#include <silkworm/silkrpc/concurrency/context_pool.hpp>
#include <silkworm/silkrpc/http/request_handler.hpp>

#include <silkworm/silkrpc/commands/rpc_api_table.hpp>

namespace silkrpc::http {

/// The top-level class of the HTTP server.
class Server {
public:
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Construct the server to listen on the specified local TCP end-point
    explicit Server(const std::string& end_point, const std::string& api_spec, Context& context, boost::asio::thread_pool& workers, std::optional<std::string> jwt_secret);

    void start();

    void stop();

private:
    static std::tuple<std::string, std::string> parse_endpoint(const std::string& tcp_end_point);

    boost::asio::awaitable<void> run();

    // The repository of API request handlers
    commands::RpcApiTable handler_table_;

    // The context used to perform asynchronous operations
    Context& context_;

    // The acceptor used to listen for incoming TCP connections
    boost::asio::ip::tcp::acceptor acceptor_;

    boost::asio::thread_pool& workers_;
    std::optional<std::string> jwt_secret_;
};

} // namespace silkrpc::http

