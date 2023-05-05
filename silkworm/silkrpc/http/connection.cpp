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

#include "connection.hpp"

#include <exception>
#include <fstream>
#include <string_view>
#include <utility>

#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>

namespace silkworm::rpc::http {

Connection::Connection(boost::asio::io_context& io_context,
                       boost::asio::thread_pool& workers,
                       commands::RpcApiTable& handler_table,
                       std::optional<std::string> jwt_secret)
    : socket_{io_context},
      request_handler_{io_context, workers, socket_, handler_table, std::move(jwt_secret)},
      buffer_{} {
    request_.content.reserve(kRequestContentInitialCapacity);
    request_.headers.reserve(kRequestHeadersInitialCapacity);
    request_.method.reserve(kRequestMethodInitialCapacity);
    request_.uri.reserve(kRequestUriInitialCapacity);
    SILKRPC_DEBUG << "Connection::Connection socket " << &socket_ << " created\n";
}

Connection::~Connection() {
    socket_.close();
    SILKRPC_DEBUG << "Connection::~Connection socket " << &socket_ << " deleted\n";
}

boost::asio::awaitable<void> Connection::read_loop() {
    try {
        // Read next request or next chunk (result == RequestParser::indeterminate) until closed or error
        while (true) {
            co_await do_read();
        }
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::asio::error::eof || se.code() == boost::asio::error::connection_reset || se.code() == boost::asio::error::broken_pipe) {
            SILKRPC_DEBUG << "Connection::read_loop close from client with code: " << se.code() << "\n"
                          << std::flush;
        } else if (se.code() != boost::asio::error::operation_aborted) {
            SILKRPC_ERROR << "Connection::read_loop system_error: " << se.what() << "\n"
                          << std::flush;
            std::rethrow_exception(std::make_exception_ptr(se));
        } else {
            SILKRPC_DEBUG << "Connection::read_loop operation_aborted: " << se.what() << "\n"
                          << std::flush;
        }
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "Connection::read_loop exception: " << e.what() << "\n"
                      << std::flush;
        std::rethrow_exception(std::make_exception_ptr(e));
    }
}

boost::asio::awaitable<void> Connection::do_read() {
    SILKRPC_DEBUG << "Connection::do_read going to read...\n"
                  << std::flush;
    std::size_t bytes_read = co_await socket_.async_read_some(boost::asio::buffer(buffer_), boost::asio::use_awaitable);
    SILKRPC_DEBUG << "Connection::do_read bytes_read: " << bytes_read << "\n";
    SILKRPC_TRACE << "Connection::do_read buffer: " << std::string_view{static_cast<const char*>(buffer_.data()), bytes_read} << "\n";

    RequestParser::ResultType result = request_parser_.parse(request_, buffer_.data(), buffer_.data() + bytes_read);

    if (result == RequestParser::ResultType::good) {
        co_await request_handler_.handle_user_request(request_);
        clean();
    } else if (result == RequestParser::ResultType::bad) {
        reply_ = Reply::stock_reply(StatusType::bad_request);
        co_await do_write();
        clean();
    } else if (result == RequestParser::ResultType::processing_continue) {
        reply_ = Reply::stock_reply(StatusType::processing_continue);
        co_await do_write();
        reply_.reset();
    }
}

boost::asio::awaitable<void> Connection::do_write() {
    SILKRPC_DEBUG << "Connection::do_write reply: " << reply_.content << "\n"
                  << std::flush;
    const auto bytes_transferred = co_await boost::asio::async_write(socket_, reply_.to_buffers(), boost::asio::use_awaitable);
    SILKRPC_TRACE << "Connection::do_write bytes_transferred: " << bytes_transferred << "\n"
                  << std::flush;
}

void Connection::clean() {
    request_.reset();
    request_parser_.reset();
    reply_.reset();
}

}  // namespace silkworm::rpc::http
