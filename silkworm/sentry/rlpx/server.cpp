// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
    const any_io_executor& executor,
    uint16_t port)
    : ip_(ip::address{ip::address_v4::any()}),
      port_(port),
      peer_channel_(executor) {}

ip::tcp::endpoint Server::listen_endpoint() const {
    return ip::tcp::endpoint{ip_, port_};
}

Task<void> Server::run(
    concurrency::ExecutorPool& executor_pool,
    EccKeyPair node_key,
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

    try {
        acceptor.bind(endpoint);
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::address_in_use) {
            throw std::runtime_error("Sentry RLPx server has failed to start because port " + std::to_string(port_) + " is already in use. Try another one with --port.");
        }
        throw;
    }
    acceptor.listen();

    EnodeUrl node_url{node_key.public_key(), endpoint.address(), port_, port_};
    SILK_INFO_M("sentry") << "rlpx::Server is listening at " << node_url.to_string();

    while (acceptor.is_open()) {
        auto client_executor = executor_pool.any_executor();
        SocketStream stream{client_executor};
        try {
            co_await acceptor.async_accept(stream.socket(), use_awaitable);
        } catch (const boost::system::system_error& ex) {
            if (ex.code() == boost::system::errc::invalid_argument) {
                SILK_ERROR_M("sentry") << "Sentry RLPx server got invalid_argument on accept port=" << port_;
                continue;
            }
            SILK_CRIT_M("sentry") << "Sentry RLPx server unexpected end [" + std::string{ex.what()} + "]";
            throw;
        }

        try {
            const auto remote_endpoint = stream.socket().remote_endpoint();
            SILK_DEBUG_M("sentry") << "rlpx::Server client connected from " << remote_endpoint;
        } catch (const boost::system::system_error& ex) {
            SILK_DEBUG_M("sentry") << "rlpx::Server client immediately disconnected [" + std::string{ex.what()} + "]";
            continue;
        }

        auto peer = std::make_shared<Peer>(
            client_executor,
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
