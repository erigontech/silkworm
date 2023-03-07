/*
    Copyright 2020 The Silkrpc Authors

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

#include <cstring>
#include <memory>
#include <string>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <silkworm/silkrpc/common/constants.hpp>
#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/http/connection.hpp>
#include <silkworm/silkrpc/http/methods.hpp>

namespace silkrpc::http {
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

Server::Server(const std::string& end_point, const std::string& api_spec, Context& context, boost::asio::thread_pool& workers, std::optional<std::string> jwt_secret)
: context_(context), workers_(workers), acceptor_{*context.io_context()}, handler_table_{api_spec}, jwt_secret_(jwt_secret) {
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
    boost::asio::co_spawn(acceptor_.get_executor(), run(), [&](std::exception_ptr eptr) {
        if (eptr) std::rethrow_exception(eptr);
    });
}

boost::asio::awaitable<void> Server::run() {
    acceptor_.listen();

    try {
        while (acceptor_.is_open()) {
            auto io_context = context_.io_context();

            SILKRPC_DEBUG << "Server::run accepting using io_context " << io_context << "...\n" << std::flush;

            auto new_connection = std::make_shared<Connection>(context_, workers_, handler_table_, jwt_secret_);
            co_await acceptor_.async_accept(new_connection->socket(), boost::asio::use_awaitable);
            if (!acceptor_.is_open()) {
                SILKRPC_TRACE << "Server::run returning...\n";
                co_return;
            }

            new_connection->socket().set_option(boost::asio::ip::tcp::socket::keep_alive(true));

            SILKRPC_TRACE << "Server::run starting connection for socket: " << &new_connection->socket() << "\n";
            auto new_connection_starter = [=]() -> boost::asio::awaitable<void> { co_await new_connection->start(); };

            boost::asio::co_spawn(*io_context, new_connection_starter, [&](std::exception_ptr eptr) {
                if (eptr) std::rethrow_exception(eptr);
            });
        }
    } catch (const boost::system::system_error& se) {
        if (se.code() != boost::asio::error::operation_aborted) {
            SILKRPC_ERROR << "Server::run system_error: " << se.what() << "\n" << std::flush;
            std::rethrow_exception(std::make_exception_ptr(se));
        } else {
            SILKRPC_DEBUG << "Server::run operation_aborted: " << se.what() << "\n" << std::flush;
        }
    }
    SILKRPC_DEBUG << "Server::run exiting...\n" << std::flush;
}

void Server::stop() {
    // The server is stopped by cancelling all outstanding asynchronous operations.
    SILKRPC_DEBUG << "Server::stop started...\n";
    acceptor_.close();
    SILKRPC_DEBUG << "Server::stop completed\n" << std::flush;
}

} // namespace silkrpc::http
