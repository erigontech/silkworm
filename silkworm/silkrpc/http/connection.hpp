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

#include <array>
#include <string>

#include <silkworm/silkrpc/config.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>

#include <silkworm/silkrpc/commands/rpc_api_table.hpp>
#include <silkworm/silkrpc/common/constants.hpp>
#include <silkworm/silkrpc/concurrency/context_pool.hpp>
#include <silkworm/silkrpc/http/reply.hpp>
#include <silkworm/silkrpc/http/request.hpp>
#include <silkworm/silkrpc/http/request_handler.hpp>
#include <silkworm/silkrpc/http/request_parser.hpp>

namespace silkrpc::http {

/// Represents a single connection from a client.
class Connection {
public:
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    /// Construct a connection running within the given execution context.
    Connection(Context& context, boost::asio::thread_pool& workers, commands::RpcApiTable& handler_table, std::optional<std::string> jwt_secret);

    ~Connection();

    boost::asio::ip::tcp::socket& socket() { return socket_; }

    /// Start the first asynchronous operation for the connection.
    boost::asio::awaitable<void> start();

private:
    // reset connection data
    void clean();

    /// Perform an asynchronous read operation.
    boost::asio::awaitable<void> do_read();

    /// Perform an asynchronous write operation.
    boost::asio::awaitable<void> do_write();

    /// Socket for the connection.
    boost::asio::ip::tcp::socket socket_;

    /// The handler used to process the incoming request.
    RequestHandler request_handler_;

    /// Buffer for incoming data.
    std::array<char, kHttpIncomingBufferSize> buffer_;

    /// The incoming request.
    Request request_;

    /// The parser for the incoming request.
    RequestParser request_parser_;

    /// The reply to be sent back to the client.
    Reply reply_;
};

} // namespace silkrpc::http

