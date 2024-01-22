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
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#include <silkworm/rpc/commands/rpc_api_table.hpp>
#include <silkworm/rpc/http/channel.hpp>
#include <silkworm/rpc/http/request_handler.hpp>

namespace silkworm::rpc::http {

//! Represents a single connection from a client via websocket.
class WebSocketConnection : public std::enable_shared_from_this<WebSocketConnection>, Channel {
  public:
    WebSocketConnection(const WebSocketConnection&) = delete;
    WebSocketConnection& operator=(const WebSocketConnection&) = delete;

    //! Construct a connection running within the given execution context.
    WebSocketConnection(boost::beast::websocket::stream<boost::beast::tcp_stream>&& stream,
                        commands::RpcApi& api,
                        const commands::RpcApiTable& handler_table);

    ~WebSocketConnection();

    template <class Body, class Allocator>
    Task<void>
    do_accept(const boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>>& req);
  
    Task<void> do_read();

    Task<void> open_stream() override { co_return; }
    Task<void> close() override { co_return; }

    Task<void> write_rsp(const std::string& content) override;
    Task<std::size_t> write(std::string_view content) override;

  private:
    //! Perform an asynchronous write operation.
    Task<void> do_write(const std::string& content);

    boost::beast::websocket::stream<boost::beast::tcp_stream> ws_;

    //! The handler used to process the incoming request.
    RequestHandler request_handler_;

    //! Buffer for incoming data.
    boost::beast::flat_buffer buffer_;
};

}  // namespace silkworm::rpc::http
