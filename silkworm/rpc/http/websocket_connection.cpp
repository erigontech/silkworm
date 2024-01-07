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

WebSocketConnection::WebSocketConnection(boost::beast::websocket::stream<boost::beast::tcp_stream>&& ws,
                                         RequestHandler&& request_handler)
    : ws_{ws}, request_handler_{request_handler}, buffer_{} {
    SILK_DEBUG << "WebSocketConnection::WebSocketConnection ws created:" << &ws_;
}

WebSocketConnection::~WebSocketConnection() {
    // socket_.close();
    SILK_DEBUG << "WebSocketConnection::~WebSocketConnection ws deleted:" << &ws_;
}

// Start the asynchronous operation
template <class Body, class Allocator>
Task<void>
WebSocketConnection::do_accept(boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req) {
#ifdef notdef
    // Set suggested timeout settings for the websocket
    ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));

    // Set a decorator to change the Server of the handshake
    ws_.set_option(websocket::stream_base::decorator(
        [](websocket::response_type& res) {
            res.set(boost::beast::http::field::server,
                    std::string(BOOST_BEAST_VERSION_STRING) + " rpcdaemon");
        }));
    // Accept the websocket handshake
    co_await ws_.async_accept(req, boost::asio::use_awaitable);
#endif
    co_await request_handler_.handle(request_);
}

Task<void>
WebSocketConnection::do_read() {
    // Read a message into our buffer
    auto txs = ws_.async_read(buffer_, boost::asio::use_awaitable);

    co_await request_handler_.handle(request_);
}

#ifdef notdef
Task<void> WebSocketConnection::do_read() {
    void
    on_write(beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);

        if (ec)
            return fail(ec, "write");

        // Clear the buffer
        buffer_.consume(buffer_.size());

        // Do another read
        do_read();
    }

    Task<void> WebSocketConnection::do_write() {
        SILK_DEBUG << "WebSocketConnection::do_write reply: " << reply_.content;
        // const auto bytes_transferred = co_await boost::asio::async_write(socket_, reply_.to_buffers(), boost::asio::use_awaitable);
        // SILK_TRACE << "WebSocketConnection::do_write bytes_transferred: " << bytes_transferred;
    }
#endif

    void WebSocketConnection::clean() {
        request_.reset();
        reply_.reset();
    }

}  // namespace silkworm::rpc::http
