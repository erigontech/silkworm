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

#include "connection.hpp"

#include <exception>
#include <fstream>
#include <string_view>

#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/websocket/rfc6455.hpp>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::rpc::ws {

Connection::Connection(boost::beast::websocket::stream<boost::beast::tcp_stream>&& stream,
                       commands::RpcApi& api,
                       const commands::RpcApiTable& handler_table,
                       bool compression)
    : ws_{std::move(stream)},
      request_handler_{this, api, handler_table},
      compression_{compression} {
    SILK_DEBUG << "ws::Connection::Connection ws created:" << &ws_;
}

Connection::~Connection() {
    SILK_TRACE << "ws::Connection::~Connection ws deleted:" << &ws_;
}

Task<void> Connection::accept(const boost::beast::http::request<boost::beast::http::string_body>& req) {
    // Set timeout settings for the websocket
    boost::beast::websocket::stream_base::timeout timeout{
        .handshake_timeout = std::chrono::seconds(30),
        .idle_timeout = std::chrono::seconds(60),
        .keep_alive_pings = true,
    };

    ws_.set_option(timeout);
    ws_.write_buffer_bytes(65536);
    ws_.auto_fragment(false);

    if (compression_) {
        boost::beast::websocket::permessage_deflate rsp_compression_option;

        ws_.get_option(rsp_compression_option);
        rsp_compression_option.server_enable = true;
        rsp_compression_option.client_enable = true;
        rsp_compression_option.server_no_context_takeover = true,
        rsp_compression_option.client_no_context_takeover = true,
        ws_.set_option(rsp_compression_option);
    }

    // Accept the websocket handshake
    co_await ws_.async_accept(req, boost::asio::use_awaitable);
}

Task<void> Connection::read_loop() {
    SILK_TRACE << "ws::Connection::run starting connection for websocket: " << &ws_;

    try {
        while (true) {
            co_await do_read();
        }
    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "ws::Connection::read_loop system_error: " << se.what();
    } catch (const std::exception& e) {
        SILK_ERROR << "ws::Connection::read_loop exception: " << e.what();
    }
}

Task<void> Connection::do_read() {
    std::string req_content;
    auto req_buffer = boost::asio::dynamic_buffer(req_content);
    const auto bytes_read = co_await ws_.async_read(req_buffer, boost::asio::use_awaitable);

    SILK_TRACE << "ws::Connection::do_read bytes_read: " << bytes_read << " [" << req_content << "]";

    auto rsp_content = co_await request_handler_.handle(req_content);
    if (rsp_content) {
        co_await do_write(*rsp_content);
    }
}

Task<std::size_t> Connection::write(std::string_view content, bool last) {
    try {
        const auto written = co_await ws_.async_write_some(last, boost::asio::buffer(content.data(), content.size()), boost::asio::use_awaitable);

        SILK_TRACE << "ws::Connection::write: [" << content.data() << "]";
        co_return written;

    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "ws::Connection::write system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "ws::Connection::write exception: " << e.what();
        throw;
    }
}

Task<std::size_t> Connection::do_write(const std::string& content) {
    try {
        const auto written = co_await ws_.async_write(boost::asio::buffer(content), boost::asio::use_awaitable);

        SILK_TRACE << "ws::Connection::do_write: [" << content << "]";
        co_return written;
    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "ws::Connection::do_write system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "ws::Connection::do_write exception: " << e.what();
        throw;
    }
}

}  // namespace silkworm::rpc::ws
