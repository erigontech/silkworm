/*
Copyright 2020-2022 The Silkworm Authors

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

#include <memory>
#include <string>
#include <utility>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <silkworm/common/log.hpp>

namespace silkworm::sentry::rlpx {

using namespace boost::asio;

Server::Server(std::string host, uint16_t port) : host_(std::move(host)), port_(port) {
}

awaitable<void> Server::start(io_context& io_context) {
    ip::tcp::resolver resolver{io_context};
    auto endpoints = co_await resolver.async_resolve(host_, std::to_string(port_), use_awaitable);
    const ip::tcp::endpoint& endpoint = *endpoints.cbegin();

    ip::tcp::acceptor acceptor{io_context, endpoint.protocol()};
    acceptor.set_option(ip::tcp::acceptor::reuse_address(true));
    acceptor.set_option(detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT>(true));
    acceptor.bind(endpoint);
    acceptor.listen();

    while (acceptor.is_open()) {
        ip::tcp::socket socket{io_context};
        co_await acceptor.async_accept(socket, use_awaitable);
    }
}

}  // namespace silkworm::sentry::rlpx
