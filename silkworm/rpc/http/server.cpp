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

#include "server.hpp"

#include <string>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
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
               RequestHandlerFactory&& handler_factory,
               boost::asio::io_context& ioc,
               WorkerPool& workers,
               std::vector<std::string> allowed_origins,
               std::optional<std::string> jwt_secret,
               bool use_websocket,
               bool ws_compression,
               bool http_compression,
               bool  rpc_compatability)
    : handler_factory_{std::move(handler_factory)},
      acceptor_{ioc},
      allowed_origins_{std::move(allowed_origins)},
      jwt_secret_(std::move(jwt_secret)),
      use_websocket_{use_websocket},
      ws_compression_{ws_compression},
      http_compression_{http_compression},
      workers_{workers},
      rpc_compatability_{rpc_compatability} {
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
    auto this_executor = co_await boost::asio::this_coro::executor;
    try {
        acceptor_.listen();
        while (acceptor_.is_open()) {
            SILK_TRACE << "Server::run accepting using executor " << &this_executor << "...";

            boost::asio::ip::tcp::socket socket{this_executor};
            co_await acceptor_.async_accept(socket, boost::asio::use_awaitable);
            if (!acceptor_.is_open()) {
                SILK_TRACE << "Server::run returning...";
                co_return;
            }

            SILK_TRACE << "Server::run accepted connection from " << socket.remote_endpoint();

            auto new_connection = std::make_shared<Connection>(
                std::move(socket), handler_factory_, allowed_origins_, jwt_secret_, use_websocket_, ws_compression_, http_compression_, workers_, rpc_compatability_);
            boost::asio::co_spawn(this_executor, Connection::run_read_loop(new_connection), boost::asio::detached);
        }
    } catch (const boost::system::system_error& se) {
        if (se.code() != boost::asio::error::operation_aborted) {
            SILK_ERROR << "Server::run system_error: " << se.what();
            std::rethrow_exception(std::make_exception_ptr(se));
        } else {
            SILK_DEBUG << "Server::run operation_aborted: " << se.what();
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "Server::run exception: " << e.what();
        std::rethrow_exception(std::make_exception_ptr(e));
    }
    SILK_DEBUG << "Server::run exiting...";
}

}  // namespace silkworm::rpc::http
