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

#include "server.hpp"

#include <memory>
#include <string>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/http/connection.hpp>

namespace silkworm::rpc::http {
#ifdef WIN32
using reuse_port = boost::asio::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEADDR>;
#else
using reuse_port = boost::asio::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT>;
#endif

std::tuple<std::string, std::string> Server::parse_endpoint(const std::string& tcp_end_point) {
    const auto host = tcp_end_point.substr(0, tcp_end_point.find(kAddressPortSeparator));
    const auto port = tcp_end_point.substr(tcp_end_point.find(kAddressPortSeparator) + 1, std::string::npos);
    return {host, port};
}

Server::Server(const std::string& end_point,
               const std::string& api_spec,
               boost::asio::io_context& io_context,
               boost::asio::thread_pool& workers,
               std::vector<std::string> allowed_origins,
               std::optional<std::string> jwt_secret)
    : rpc_api_{io_context, workers},
      handler_table_{api_spec},
      io_context_(io_context),
      acceptor_{io_context},
      allowed_origins_{allowed_origins},
      jwt_secret_(std::move(jwt_secret)) {
    const auto [host, port] = parse_endpoint(end_point);

    // Open the acceptor with the option to reuse the address (i.e. SO_REUSEADDR).
    boost::asio::ip::tcp::resolver resolver{acceptor_.get_executor()};
    boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(host, port).begin();
    acceptor_.open(endpoint.protocol());
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.set_option(reuse_port(true));
    acceptor_.bind(endpoint);
}

void Server::start() {
    boost::asio::co_spawn(acceptor_.get_executor(), run(), [&](const std::exception_ptr& eptr) {
        if (eptr) std::rethrow_exception(eptr);
    });
}

Task<void> Server::run() {
    acceptor_.listen();

    try {
        while (acceptor_.is_open()) {
            SILK_DEBUG << "Server::run accepting using io_context " << &io_context_ << "...";

            auto new_connection = std::make_shared<Connection>(io_context_, rpc_api_, handler_table_, allowed_origins_, jwt_secret_);
            co_await acceptor_.async_accept(new_connection->socket(), boost::asio::use_awaitable);
            if (!acceptor_.is_open()) {
                SILK_TRACE << "Server::run returning...";
                co_return;
            }

            new_connection->socket().set_option(boost::asio::ip::tcp::socket::keep_alive(true));

            SILK_TRACE << "Server::run starting connection for socket: " << &new_connection->socket();
            auto connection_loop = [=]() -> Task<void> { co_await new_connection->read_loop(); };

            boost::asio::co_spawn(io_context_, connection_loop, [&](const std::exception_ptr& eptr) {
                if (eptr) std::rethrow_exception(eptr);
            });
        }
    } catch (const boost::system::system_error& se) {
        if (se.code() != boost::asio::error::operation_aborted) {
            SILK_ERROR << "Server::run system_error: " << se.what();
            std::rethrow_exception(std::make_exception_ptr(se));
        } else {
            SILK_DEBUG << "Server::run operation_aborted: " << se.what();
        }
    }
    SILK_DEBUG << "Server::run exiting...";
}

void Server::stop() {
    // The server is stopped by cancelling all outstanding asynchronous operations.
    SILK_DEBUG << "Server::stop started...";
    acceptor_.close();
    SILK_DEBUG << "Server::stop completed";
}

}  // namespace silkworm::rpc::http
