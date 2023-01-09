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

#include "client.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/sentry/common/random.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>

namespace silkworm::sentry::rlpx {

using namespace boost::asio;

awaitable<void> Client::start(
    silkworm::rpc::ServerContextPool& context_pool,
    common::EccKeyPair node_key,
    std::string client_id,
    uint16_t node_listen_port,
    std::function<std::unique_ptr<Protocol>()> protocol_factory) {
    auto start = this->start_in_strand(context_pool, node_key, client_id, node_listen_port, protocol_factory);
    co_await co_spawn(strand_, std::move(start), use_awaitable);
}

awaitable<void> Client::start_in_strand(
    silkworm::rpc::ServerContextPool& context_pool,
    common::EccKeyPair node_key,
    std::string client_id,
    uint16_t node_listen_port,
    std::function<std::unique_ptr<Protocol>()> protocol_factory) {
    auto& peers = peers_;
    if (peer_urls_.empty()) {
        co_return;
    }
    auto& peer_url = peer_urls_.front();
    auto& client_context = context_pool.next_io_context();

    ip::tcp::resolver resolver{client_context};
    auto endpoints = co_await resolver.async_resolve(
        peer_url.ip().to_string(),
        std::to_string(peer_url.port()),
        use_awaitable);
    const ip::tcp::endpoint& endpoint = *endpoints.cbegin();

    common::SocketStream stream{client_context};
    co_await stream.socket().async_connect(endpoint, use_awaitable);

    auto remote_endpoint = stream.socket().remote_endpoint();
    log::Debug() << "RLPx client connected to "
                 << remote_endpoint.address().to_string() << ":" << remote_endpoint.port();

    auto peer = std::make_unique<Peer>(
        client_context,
        std::move(stream),
        node_key,
        client_id,
        node_listen_port,
        protocol_factory(),
        std::optional{peer_url.public_key()});
    peers.emplace_back(std::move(peer));

    co_await peers.front()->handle();
}

awaitable<void> Client::enumerate_peers(std::function<awaitable<void>(Peer&)> callback) {
    co_await co_spawn(strand_, enumerate_peers_in_strand(callback), use_awaitable);
}

awaitable<void> Client::enumerate_random_peer(std::function<awaitable<void>(Peer&)> callback) {
    co_await co_spawn(strand_, enumerate_random_peer_in_strand(callback), use_awaitable);
}

awaitable<void> Client::enumerate_peers_in_strand(std::function<awaitable<void>(Peer&)> callback) {
    // TODO: test if this is needed
    [[maybe_unused]] auto executor = co_await this_coro::executor;
    for (auto& peer : peers_) {
        co_await callback(*peer);
    }
}

awaitable<void> Client::enumerate_random_peer_in_strand(std::function<awaitable<void>(Peer&)> callback) {
    // TODO: test if this is needed
    [[maybe_unused]] auto executor = co_await this_coro::executor;
    auto item_opt = common::random_list_item(peers_);
    if (item_opt) {
        auto& peer = **item_opt.value();
        co_await callback(peer);
    }
}

}  // namespace silkworm::sentry::rlpx
