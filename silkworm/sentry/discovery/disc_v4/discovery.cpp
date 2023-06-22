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

#include "discovery.hpp"

#include <silkworm/infra/common/log.hpp>

#include "message_handler.hpp"
#include "ping/ping_handler.hpp"
#include "server.hpp"

namespace silkworm::sentry::discovery::disc_v4 {

class DiscoveryImpl : private MessageHandler {
  public:
    DiscoveryImpl(uint16_t server_port, std::function<common::EccKeyPair()> node_key)
        : server_(server_port, std::move(node_key), *this) {}
    ~DiscoveryImpl() override = default;

    DiscoveryImpl(const DiscoveryImpl&) = delete;
    DiscoveryImpl& operator=(const DiscoveryImpl&) = delete;

    Task<void> run() {
        co_await server_.run();
    }

  private:
    Task<void> on_find_node(find::FindNodeMessage /*message*/) override {
        co_return;
    }

    Task<void> on_neighbors(find::NeighborsMessage /*message*/) override {
        co_return;
    }

    Task<void> on_ping(ping::PingMessage message, boost::asio::ip::udp::endpoint sender_endpoint, Bytes ping_packet_hash) override {
        return ping::PingHandler::handle(std::move(message), std::move(sender_endpoint), std::move(ping_packet_hash), server_);
    }

    Task<void> on_pong(ping::PongMessage /*message*/) override {
        co_return;
    }

  private:
    Server server_;
};

Discovery::Discovery(uint16_t server_port, std::function<common::EccKeyPair()> node_key)
    : p_impl_(std::make_unique<DiscoveryImpl>(server_port, std::move(node_key))) {}

Discovery::~Discovery() {
    log::Trace("sentry") << "silkworm::sentry::discovery::disc_v4::Discovery::~Discovery";
}

Task<void> Discovery::run() {
    return p_impl_->run();
}

}  // namespace silkworm::sentry::discovery::disc_v4
