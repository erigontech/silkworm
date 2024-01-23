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

#include "websocket_connection.hpp"

#include <exception>
#include <fstream>
#include <string_view>

#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/websocket/rfc6455.hpp>
#include <boost/system/error_code.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace beast = boost::beast;          // from <boost/beast.hpp>
namespace http = beast::http;            // from <boost/beast/http.hpp>
namespace websocket = beast::websocket;  // from <boost/beast/websocket.hpp>
namespace net = boost::asio;             // from <boost/asio.hpp>

namespace silkworm::rpc::http {

WebSocketConnection::WebSocketConnection(boost::beast::websocket::stream<boost::beast::tcp_stream>&& stream,
                                         commands::RpcApi& api,
                                         const commands::RpcApiTable& handler_table)
    : ws_{std::move(stream)},
      request_handler_{this, api, handler_table} {
    SILK_DEBUG << "WebSocketConnection::WebSocketConnection ws created:" << &ws_;
}

WebSocketConnection::~WebSocketConnection() {
    // socket_.close();
    SILK_DEBUG << "WebSocketConnection::~WebSocketConnection ws deleted:" << &ws_;
}

Task<void>
WebSocketConnection::do_accept(const boost::beast::http::request<boost::beast::http::string_body>& req) {
    // Set suggested timeout settings for the websocket
    ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));

    // Accept the websocket handshake
    co_await ws_.async_accept(req, boost::asio::use_awaitable);
}

Task<void> WebSocketConnection::read_loop() {
    try {
        while (true) {
            co_await do_read();
        }
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::beast::http::error::end_of_stream || se.code() == boost::asio::error::broken_pipe ||
            se.code() == boost::asio::error::connection_reset) {
            SILK_TRACE << "WebSocketConnection::read_loop close from client with code: " << se.code();
        } else if (se.code() != boost::asio::error::operation_aborted) {
            SILK_ERROR << "WebSocketConnection::read_loop system_error: " << se.what();
            throw;
        } else {
            SILK_TRACE << "WebSocketConnection::read_loop operation_aborted: " << se.what();
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "WebSocketConnection::read_loop exception: " << e.what();
        throw;
    }
}

Task<void>
WebSocketConnection::do_read() {
    std::string content;
    auto buf = boost::asio::dynamic_buffer(content);
    auto txs = co_await ws_.async_read(buf, boost::asio::use_awaitable);

    SILK_TRACE << "WebSocketConnection::do_read bytes_read: " << txs << "[" << content << "]\n";

    co_await request_handler_.handle(content);
}

Task<void> WebSocketConnection::write_rsp(const std::string& content) {
    co_await do_write(content);
}

Task<std::size_t> WebSocketConnection::write(std::string_view content) {
    co_await do_write(content.data());

    co_return content.size();
}

Task<void> WebSocketConnection::do_write(const std::string& content) {
    try {
        co_await ws_.async_write(boost::asio::buffer(content), boost::asio::use_awaitable);

        SILK_TRACE << "WebSocketConnection::do_write: "
                   << "[" << content << "]\n";

    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "WebSocketConnection::open_stream system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "WebSocketConnection::open_stream exception: " << e.what();
        throw;
    }
}

}  // namespace silkworm::rpc::http
