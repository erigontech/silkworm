// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "connection.hpp"

#include <exception>
#include <fstream>
#include <string_view>

#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/websocket/rfc6455.hpp>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::rpc::ws {

Connection::Connection(TcpStream&& stream,
                       RequestHandlerFactory& handler_factory,
                       bool compression)
    : stream_{std::move(stream)},
      handler_{handler_factory(this)},
      compression_{compression} {
    SILK_TRACE << "ws::Connection::Connection socket created:" << &stream_;
}

Connection::~Connection() {
    SILK_TRACE << "ws::Connection::~Connection socket deleted:" << &stream_;
}

Task<void> Connection::accept(const boost::beast::http::request<boost::beast::http::string_body>& req) {
    // Set timeout settings for the websocket
    boost::beast::websocket::stream_base::timeout timeout{
        .handshake_timeout = std::chrono::seconds(30),
        .idle_timeout = std::chrono::seconds(60),
        .keep_alive_pings = true,
    };

    stream_.set_option(timeout);
    stream_.write_buffer_bytes(65536);
    stream_.auto_fragment(false);

    if (compression_) {
        boost::beast::websocket::permessage_deflate permessage_deflate{
            .server_enable = true,
            .client_enable = true,
            .server_no_context_takeover = true,
            .client_no_context_takeover = true,
        };

        stream_.set_option(permessage_deflate);
    }

    // Accept the WebSocket handshake
    co_await stream_.async_accept(req, boost::asio::use_awaitable);
}

Task<void> Connection::read_loop() {
    SILK_TRACE << "ws::Connection::run starting connection for socket: " << &stream_;

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
    const auto bytes_read = co_await stream_.async_read(req_buffer, boost::asio::use_awaitable);

    SILK_TRACE << "ws::Connection::do_read bytes_read: " << bytes_read << " [" << req_content << "]";

    auto rsp_content = co_await handler_->handle(req_content, 0);
    if (rsp_content) {
        co_await do_write(*rsp_content);
    }
}

Task<size_t> Connection::write(uint64_t /* request_id */, std::string_view content, bool last) {
    try {
        const auto written = co_await stream_.async_write_some(last, boost::asio::buffer(content.data(), content.size()), boost::asio::use_awaitable);

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

Task<size_t> Connection::do_write(const std::string& content) {
    try {
        const auto written = co_await stream_.async_write(boost::asio::buffer(content), boost::asio::use_awaitable);

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
