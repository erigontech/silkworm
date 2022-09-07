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

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>

#include "peer.hpp"

namespace silkworm::sentry::rlpx {

using namespace boost::asio;

awaitable<void> Client::start(
    common::EccKeyPair node_key,
    std::string client_id,
    uint16_t node_listen_port) {
    if (peer_urls_.empty()) {
        co_return;
    }
    auto& peer_url = peer_urls_.front();

    auto executor = co_await this_coro::executor;

    ip::tcp::resolver resolver{executor};
    auto endpoints = co_await resolver.async_resolve(
        peer_url.ip().to_string(),
        std::to_string(peer_url.port()),
        use_awaitable);
    const ip::tcp::endpoint& endpoint = *endpoints.cbegin();

    common::SocketStream stream{executor};
    co_await stream.socket().async_connect(endpoint, use_awaitable);

    auto remote_endpoint = stream.socket().remote_endpoint();
    log::Debug() << "RLPx client connected to "
                 << remote_endpoint.address().to_string() << ":" << remote_endpoint.port();

    Peer peer{
        std::move(stream),
        node_key,
        client_id,
        node_listen_port,
        {peer_url.public_key()},
    };

    co_await peer.handle();
}

}  // namespace silkworm::sentry::rlpx
