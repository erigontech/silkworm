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
//
// Copyright (c) 2003-2020 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <array>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>

#include <silkworm/rpc/commands/rpc_api_table.hpp>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/http/channel.hpp>
#include <silkworm/rpc/http/reply.hpp>
#include <silkworm/rpc/http/request.hpp>
#include <silkworm/rpc/http/request_handler.hpp>
#include <silkworm/rpc/http/request_parser.hpp>

namespace silkworm::rpc::http {

//! Represents a single connection from a client.
class Connection : public Channel {
  public:
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    

    //! Construct a connection running within the given execution context.
    Connection(boost::asio::io_context& io_context,
               commands::RpcApi& api,
               commands::RpcApiTable& handler_table,
               const std::vector<std::string>& allowed_origins,
               std::optional<std::string> jwt_secret);
    virtual ~Connection();

    boost::asio::ip::tcp::socket& socket() { return socket_; }

    //! Start the asynchronous read loop for the connection.
    Task<void> read_loop();

    Task<void> write_rsp(Response& response) override;
    Task<void> open() override;
    Task<std::size_t> write(std::string_view content) override;
    Task<void> close() override { co_return; }

  private:
    using AuthorizationError = std::string;
    using AuthorizationResult = tl::expected<void, AuthorizationError>;
    AuthorizationResult is_request_authorized(const http::Request& request);

    Task<void> handle_request(Request& request);

    //! Reset connection data
    void clean();

    void set_cors(std::vector<Header>& headers);

    Task<void> write_headers();

    static StatusType get_http_status(Channel::ResponseStatus status);

    //! Perform an asynchronous read operation.
    Task<void> do_read();

    //! Perform an asynchronous write operation.
    Task<void> do_write();
    Task<void> do_write(http::Reply& reply);

    //! Socket for the connection.
    boost::asio::ip::tcp::socket socket_;

    //! The handler used to process the incoming request.
    RequestHandler request_handler_;

    //! Buffer for incoming data.
    std::array<char, kHttpIncomingBufferSize> buffer_;

    //! The incoming request.
    Request request_;

    //! The parser for the incoming request.
    RequestParser request_parser_;

    //! The reply to be sent back to the client.
    Reply reply_;

    const std::vector<std::string>& allowed_origins_;

    const std::optional<std::string> jwt_secret_;
};

}  // namespace silkworm::rpc::http
