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

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/use_promise.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/websocket/rfc6455.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/co_spawn_sw.hpp>

namespace silkworm::rpc::ws {

//! The default ping interval
constexpr std::chrono::milliseconds kDefaultPingInterval{60'000};

Connection::Connection(boost::beast::websocket::stream<boost::beast::tcp_stream>&& stream,
                       commands::RpcApi& api,
                       const commands::RpcApiTable& handler_table)
    : ws_{std::move(stream)},
      request_handler_{this, api, handler_table},
      ping_timer_{ws_.get_executor()} {
    SILK_DEBUG << "ws::Connection::Connection ws created:" << &ws_;
}

Connection::~Connection() {
    SILK_TRACE << "ws::Connection::~Connection ws deleted:" << &ws_;
}

Task<void> Connection::accept(const boost::beast::http::request<boost::beast::http::string_body>& req) {
    // Set suggested timeout settings for the websocket
    ws_.set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::server));

    // Accept the websocket handshake
    co_await ws_.async_accept(req, boost::asio::use_awaitable);
}

Task<void> Connection::ping_loop() {
    while (true) {
        ping_timer_.expires_after(kDefaultPingInterval);
        const auto [ec] = co_await ping_timer_.async_wait(as_tuple(boost::asio::use_awaitable));
        if (ec == boost::asio::error::operation_aborted) {
            continue;
        }
        try {
            co_await ws_.async_ping("", boost::asio::use_awaitable);
        } catch (const boost::system::system_error& se) {
            SILK_TRACE << "ws::Connection::ping_loop system_error: " << se.what();
            throw;
        } catch (const std::exception& e) {
            SILK_ERROR << "ws::Connection::ping_loop exception: " << e.what();
            throw;
        }
    }
}

Task<void> Connection::read_loop() {
    using RunPromise = boost::asio::experimental::promise<void(std::exception_ptr)>;
    RunPromise run_completion_promise{concurrency::co_spawn_sw(
        ws_.get_executor(),
        ping_loop(),
        boost::asio::experimental::use_promise)};

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

    co_await run_completion_promise(boost::asio::use_awaitable);
    ping_timer_.cancel();
}

Task<void> Connection::do_read() {
    std::string content;
    auto buf = boost::asio::dynamic_buffer(content);
    const auto bytes_read = co_await ws_.async_read(buf, boost::asio::use_awaitable);

    SILK_TRACE << "ws::Connection::do_read bytes_read: " << bytes_read << "[" << content << "]";

    co_await request_handler_.handle(content);
}

Task<void> Connection::write_rsp(const std::string& content) {
    co_await do_write(content);
}

Task<std::size_t> Connection::write(std::string_view content) {
    co_return co_await do_write(content.data());
}

Task<std::size_t> Connection::do_write(const std::string& content) {
    try {
        const auto written = co_await ws_.async_write(boost::asio::buffer(content), boost::asio::use_awaitable);

        SILK_TRACE << "ws::Connection::do_write: [" << content << "]";
        ping_timer_.cancel();
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
