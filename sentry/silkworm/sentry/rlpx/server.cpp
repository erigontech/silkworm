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

#include <future>
#include <list>
#include <memory>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/sentry/common/enode_url.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>

#include "peer.hpp"

namespace silkworm::sentry::rlpx {

using namespace boost::asio;

Server::Server(std::string host, uint16_t port) : host_(std::move(host)), port_(port) {}

awaitable<void> Server::start(
    silkworm::rpc::ServerContextPool& context_pool,
    common::EccKeyPair node_key,
    std::string client_id) {
    auto executor = co_await this_coro::executor;

    ip::tcp::resolver resolver{executor};
    auto endpoints = co_await resolver.async_resolve(host_, std::to_string(port_), use_awaitable);
    const ip::tcp::endpoint& endpoint = *endpoints.cbegin();

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

    std::list<std::pair<std::unique_ptr<Peer>, std::future<void>>> peers;

    while (acceptor.is_open()) {
        auto& client_context = context_pool.next_io_context();
        common::SocketStream stream{client_context};
        co_await acceptor.async_accept(stream.socket(), use_awaitable);

        auto remote_endpoint = stream.socket().remote_endpoint();
        log::Debug() << "RLPx server client connected from "
                     << remote_endpoint.address().to_string() << ":" << remote_endpoint.port();

        auto peer = std::make_unique<Peer>(
            std::move(stream),
            node_key,
            client_id,
            port_,
            std::nullopt);
        auto handler = co_spawn(client_context, peer->handle(), use_future);

        peers.emplace_back(std::move(peer), std::move(handler));
    }

    while (!peers.empty()) {
        auto& peer = peers.front();
        // TODO: graceful shutdown
        // peer.first->disconnect();
        peer.second.wait();
        peers.pop_front();
    }
}

}  // namespace silkworm::sentry::rlpx
