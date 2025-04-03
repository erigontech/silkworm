// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/sentry/common/ecc_key_pair.hpp>

#include "message_handler.hpp"
#include "message_sender.hpp"

namespace silkworm::sentry::discovery::disc_v4 {

class ServerImpl;

class Server : public MessageSender {
  public:
    Server(
        const boost::asio::any_io_executor& executor,
        uint16_t port,
        std::function<EccKeyPair()> node_key,
        MessageHandler& handler);
    ~Server() override;

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    void setup();
    Task<void> run();

    Task<void> send_ping(ping::PingMessage message, boost::asio::ip::udp::endpoint recipient) override;
    Task<void> send_pong(ping::PongMessage message, boost::asio::ip::udp::endpoint recipient) override;
    Task<void> send_find_node(find::FindNodeMessage message, boost::asio::ip::udp::endpoint recipient) override;
    Task<void> send_neighbors(find::NeighborsMessage message, boost::asio::ip::udp::endpoint recipient) override;
    Task<void> send_enr_request(enr::EnrRequestMessage message, boost::asio::ip::udp::endpoint recipient) override;
    Task<void> send_enr_response(enr::EnrResponseMessage message, boost::asio::ip::udp::endpoint recipient) override;

  private:
    std::unique_ptr<ServerImpl> p_impl_;
};

}  // namespace silkworm::sentry::discovery::disc_v4
