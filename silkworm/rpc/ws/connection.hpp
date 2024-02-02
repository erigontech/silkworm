/*
   Copyright 2024 The Silkworm Authors

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

#pragma once

#include <array>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#include <silkworm/rpc/commands/rpc_api_table.hpp>
#include <silkworm/rpc/http/channel.hpp>
#include <silkworm/rpc/http/request_handler.hpp>

namespace silkworm::rpc::ws {

//! Represents a single connection from a client via websocket.
class Connection : public Channel {
  public:
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    //! Construct a connection running within the given execution context.
    Connection(boost::beast::websocket::stream<boost::beast::tcp_stream>&& stream,
               commands::RpcApi& api,
               const commands::RpcApiTable& handler_table,
               bool ws_compression = false);

    ~Connection() override;

    Task<void> accept(const boost::beast::http::request<boost::beast::http::string_body>& req);

    Task<void> read_loop();

    // Methods of Channel interface
    Task<void> open_stream() override { co_return; }
    Task<void> close() override { co_return; }
    Task<void> write_rsp(const std::string& content) override;
    Task<std::size_t> write(std::string_view content) override;

  private:
    Task<void> do_read();

    //! Perform an asynchronous write operation.
    Task<std::size_t> do_write(const std::string& content);

    // websocket stream
    boost::beast::websocket::stream<boost::beast::tcp_stream> ws_;

    //! The handler used to process the incoming request.
    http::RequestHandler request_handler_;

    //! enable compress flag
    bool ws_compression_{false};
};

}  // namespace silkworm::rpc::ws
