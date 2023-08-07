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

#include <boost/signals2.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/event_notifier.hpp>
#include <silkworm/sentry/common/sleep.hpp>

#include "find/find_node_handler.hpp"
#include "find/lookup.hpp"
#include "message_handler.hpp"
#include "ping/ping_check.hpp"
#include "ping/ping_handler.hpp"
#include "server.hpp"

namespace silkworm::sentry::discovery::disc_v4 {

class DiscoveryImpl : private MessageHandler {
  public:
    DiscoveryImpl(
        boost::asio::any_io_executor executor,
        uint16_t server_port,
        std::function<EccKeyPair()> node_key,
        std::function<EnodeUrl()> node_url,
        node_db::NodeDb& node_db)
        : server_(server_port, std::move(node_key), *this),
          node_url_(std::move(node_url)),
          node_db_(node_db),
          discover_more_needed_notifier_(executor) {}
    ~DiscoveryImpl() override = default;

    DiscoveryImpl(const DiscoveryImpl&) = delete;
    DiscoveryImpl& operator=(const DiscoveryImpl&) = delete;

    Task<void> run() {
        using namespace concurrency::awaitable_wait_for_all;
        co_await (server_.run() && discover_more() && periodic_ping_check());
    }

    void discover_more_needed() {
        discover_more_needed_notifier_.notify();
    }

  private:
    Task<void> on_find_node(find::FindNodeMessage message, EccPublicKey sender_public_key, boost::asio::ip::udp::endpoint sender_endpoint) override {
        return find::FindNodeHandler::handle(std::move(message), std::move(sender_public_key), std::move(sender_endpoint), server_, node_db_);
    }

    Task<void> on_neighbors(find::NeighborsMessage message, EccPublicKey sender_public_key) override {
        on_neighbors_signal_(std::move(message), std::move(sender_public_key));
        co_return;
    }

    Task<void> on_ping(ping::PingMessage message, boost::asio::ip::udp::endpoint sender_endpoint, Bytes ping_packet_hash) override {
        return ping::PingHandler::handle(std::move(message), std::move(sender_endpoint), std::move(ping_packet_hash), server_);
    }

    Task<void> on_pong(ping::PongMessage message, EccPublicKey sender_public_key) override {
        on_pong_signal_(std::move(message), std::move(sender_public_key));
        co_return;
    }

    Task<void> discover_more() {
        using namespace std::chrono_literals;
        auto local_node_id = node_url_().public_key();

        while (true) {
            co_await discover_more_needed_notifier_.wait();

            auto total_neighbors = co_await find::lookup(local_node_id, server_, on_neighbors_signal_, node_db_);

            if (total_neighbors == 0) {
                co_await sleep(10s);
                discover_more_needed_notifier_.notify();
            }
        }
    }

    Task<void> periodic_ping_check() {
        using namespace std::chrono_literals;
        auto local_node_url = node_url_();

        while (true) {
            auto now = std::chrono::system_clock::now();
            auto node_ids = co_await node_db_.find_ping_candidates(now, 10);
            if (node_ids.empty()) {
                co_await sleep(10s);
                continue;
            }

            for (auto& node_id : node_ids) {
                try {
                    co_await ping::ping_check(node_id, std::nullopt, local_node_url, server_, on_pong_signal_, node_db_);
                } catch (const boost::system::system_error& ex) {
                    if (ex.code() == boost::system::errc::operation_canceled)
                        throw;
                    log::Error("sentry") << "disc_v4::DiscoveryImpl::periodic_ping_check ping_check node_id=" << node_id.hex() << " system_error: " << ex.what();
                } catch (const std::exception& ex) {
                    log::Error("sentry") << "disc_v4::DiscoveryImpl::periodic_ping_check ping_check node_id=" << node_id.hex() << " exception: " << ex.what();
                }
            }
        }
    }

    Server server_;
    [[maybe_unused]] std::function<EnodeUrl()> node_url_;
    [[maybe_unused]] node_db::NodeDb& node_db_;
    concurrency::EventNotifier discover_more_needed_notifier_;
    boost::signals2::signal<void(find::NeighborsMessage, EccPublicKey)> on_neighbors_signal_;
    boost::signals2::signal<void(ping::PongMessage, EccPublicKey)> on_pong_signal_;
};

Discovery::Discovery(
    boost::asio::any_io_executor executor,
    uint16_t server_port,
    std::function<EccKeyPair()> node_key,
    std::function<EnodeUrl()> node_url,
    node_db::NodeDb& node_db)
    : p_impl_(std::make_unique<DiscoveryImpl>(std::move(executor), server_port, std::move(node_key), std::move(node_url), node_db)) {}

Discovery::~Discovery() {
    log::Trace("sentry") << "silkworm::sentry::discovery::disc_v4::Discovery::~Discovery";
}

Task<void> Discovery::run() {
    return p_impl_->run();
}

void Discovery::discover_more_needed() {
    p_impl_->discover_more_needed();
}

}  // namespace silkworm::sentry::discovery::disc_v4
