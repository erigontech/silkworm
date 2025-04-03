// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <memory>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/executor_pool.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>

#include "peer.hpp"
#include "protocol.hpp"

namespace silkworm::sentry::rlpx {

class Server final {
  public:
    Server(
        const boost::asio::any_io_executor& executor,
        uint16_t port);

    Task<void> run(
        concurrency::ExecutorPool& executor_pool,
        EccKeyPair node_key,
        std::string client_id,
        std::function<std::unique_ptr<Protocol>()> protocol_factory);

    const boost::asio::ip::address& ip() const { return ip_; }
    boost::asio::ip::tcp::endpoint listen_endpoint() const;

    concurrency::Channel<std::shared_ptr<Peer>>& peer_channel() {
        return peer_channel_;
    }

  private:
    boost::asio::ip::address ip_;
    uint16_t port_;
    concurrency::Channel<std::shared_ptr<Peer>> peer_channel_;
};

}  // namespace silkworm::sentry::rlpx
