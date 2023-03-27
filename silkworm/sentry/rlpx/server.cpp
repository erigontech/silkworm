/*
   Copyright 2022 The Silkworm Authors

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

#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/sentry/common/enode_url.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>

namespace silkworm::sentry::rlpx {

using namespace boost::asio;

Server::Server(
    io_context& io_context,
    uint16_t port)
    : ip_(ip::address{ip::address_v4::any()}),
      port_(port),
      peer_channel_(io_context) {}

ip::tcp::endpoint Server::listen_endpoint() const {
    return ip::tcp::endpoint{ip_, port_};
}

awaitable<void> Server::start(
    silkworm::rpc::ServerContextPool& context_pool,
    common::EccKeyPair node_key,
    std::string client_id,
    std::function<std::unique_ptr<Protocol>()> protocol_factory) {
    auto executor = co_await this_coro::executor;

    auto endpoint = listen_endpoint();

    ip::tcp::acceptor acceptor{executor, endpoint.protocol()};
    acceptor.set_option(ip::tcp::acceptor::reuse_address(true));

#if defined(_WIN32)
    // Windows does not have SO_REUSEPORT
    // see portability notes https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ
    acceptor.set_option(detail::socket_option::boolean<SOL_SOCKET, SO_EXCLUSIVEADDRUSE>(true));
#else
    acceptor.set_option(detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT>(true));
#endif

    acceptor.bind(endpoint);
    acceptor.listen();

    common::EnodeUrl node_url{node_key.public_key(), endpoint.address(), port_};
    log::Info() << "RLPx server is listening at " << node_url.to_string();

    while (acceptor.is_open()) {
        auto& client_context = context_pool.next_io_context();
        common::SocketStream stream{client_context};
        co_await acceptor.async_accept(stream.socket(), use_awaitable);

        auto remote_endpoint = stream.socket().remote_endpoint();
        log::Debug() << "RLPx server client connected from "
                     << remote_endpoint.address().to_string() << ":" << remote_endpoint.port();

        auto peer = std::make_shared<Peer>(
            client_context,
            std::move(stream),
            node_key,
            client_id,
            port_,
            protocol_factory(),
            /* url = */ std::nullopt,
            /* peer_public_key = */ std::nullopt,
            /* is_inbound = */ true,
            /* is_static = */ false);

        co_await peer_channel_.send(std::move(peer));
    }
}

}  // namespace silkworm::sentry::rlpx
