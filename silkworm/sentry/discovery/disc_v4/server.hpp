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

#pragma once

#include <functional>
#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/sentry/common/ecc_key_pair.hpp>

#include "message_handler.hpp"
#include "message_sender.hpp"

namespace silkworm::sentry::discovery::disc_v4 {

class ServerImpl;

class Server : public MessageSender {
  public:
    Server(uint16_t port, std::function<common::EccKeyPair()> node_key, MessageHandler& handler);
    ~Server() override;

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    Task<void> run();

    Task<void> send_ping(ping::PingMessage message, boost::asio::ip::udp::endpoint recipient) override;
    Task<void> send_pong(ping::PongMessage message, boost::asio::ip::udp::endpoint recipient) override;
    Task<void> send_find_node(find::FindNodeMessage message, boost::asio::ip::udp::endpoint recipient) override;
    Task<void> send_neighbors(find::NeighborsMessage message, boost::asio::ip::udp::endpoint recipient) override;

  private:
    std::unique_ptr<ServerImpl> p_impl_;
};

}  // namespace silkworm::sentry::discovery::disc_v4
