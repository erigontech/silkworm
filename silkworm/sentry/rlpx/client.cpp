// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "client.hpp"

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/sleep.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>

namespace silkworm::sentry::rlpx {

using namespace std::chrono_literals;
using namespace boost::asio;

Task<std::unique_ptr<Peer>> Client::connect(
    EnodeUrl peer_url,
    bool is_static_peer) {
    SILK_TRACE_M("sentry") << "rlpx::Client connecting to " << peer_url.to_string();

    auto client_context = co_await boost::asio::this_coro::executor;

    ip::tcp::resolver resolver{client_context};
    auto endpoints = co_await resolver.async_resolve(
        peer_url.ip().to_string(),
        std::to_string(peer_url.port_rlpx()),
        use_awaitable);
    const ip::tcp::endpoint& endpoint = *endpoints.cbegin();

    SocketStream stream{client_context};

    bool is_connected = false;
    size_t attempt_num = 0;

    while (!is_connected) {
        try {
            ++attempt_num;
            co_await stream.socket().async_connect(endpoint, use_awaitable);
            const auto remote_endpoint = stream.socket().remote_endpoint();
            SILK_TRACE_M("sentry") << "rlpx::Client connected to " << remote_endpoint;
            is_connected = true;
        } catch (const boost::system::system_error& ex) {
            if (ex.code() == boost::system::errc::operation_canceled)
                throw;
            if (attempt_num >= max_retries_)
                throw;
            SILK_DEBUG_M("sentry")
                << "rlpx::Client failed to connect"
                << " to " << peer_url.to_string()
                << " due to exception: " << ex.what()
                << ", reconnecting...";
        }
        if (!is_connected) {
            stream = SocketStream{client_context};
            co_await sleep(10s);
        }
    }

    co_return std::make_unique<Peer>(
        client_context,
        std::move(stream),
        node_key_,
        client_id_,
        node_listen_port_,
        protocol_factory_(),
        std::optional{peer_url},
        std::optional{peer_url.public_key()},
        /* is_inbound = */ false,
        /* is_static = */ is_static_peer);
}

}  // namespace silkworm::sentry::rlpx
