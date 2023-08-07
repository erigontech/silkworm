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

#include <chrono>

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>

#include "disc_v4/discovery.hpp"
#include "disc_v4/ping/ping_check.hpp"
#include "node_db/node_db_sqlite.hpp"

namespace silkworm::sentry::discovery {

using namespace boost::asio;

class DiscoveryImpl {
  public:
    explicit DiscoveryImpl(
        std::function<boost::asio::any_io_executor()> executor_pool,
        std::vector<EnodeUrl> peer_urls,
        bool with_dynamic_discovery,
        const std::filesystem::path& data_dir_path,
        std::function<EccKeyPair()> node_key,
        std::function<EnodeUrl()> node_url,
        uint16_t disc_v4_port);

    DiscoveryImpl(const DiscoveryImpl&) = delete;
    DiscoveryImpl& operator=(const DiscoveryImpl&) = delete;

    Task<void> run();

    Task<std::vector<EnodeUrl>> request_peer_urls(
        size_t max_count,
        std::vector<EnodeUrl> exclude_urls);

    bool is_static_peer_url(const EnodeUrl& peer_url);

    Task<void> on_peer_disconnected(EccPublicKey peer_public_key, bool is_useless);

  private:
    void setup_node_db();

    const std::vector<EnodeUrl> peer_urls_;
    bool with_dynamic_discovery_;
    std::filesystem::path data_dir_path_;
    node_db::NodeDbSqlite node_db_;
    disc_v4::Discovery disc_v4_discovery_;
};

DiscoveryImpl::DiscoveryImpl(
    std::function<boost::asio::any_io_executor()> executor_pool,
    std::vector<EnodeUrl> peer_urls,
    bool with_dynamic_discovery,
    const std::filesystem::path& data_dir_path,
    std::function<EccKeyPair()> node_key,
    std::function<EnodeUrl()> node_url,
    uint16_t disc_v4_port)
    : peer_urls_(std::move(peer_urls)),
      with_dynamic_discovery_(with_dynamic_discovery),
      data_dir_path_(data_dir_path),
      node_db_(executor_pool()),
      disc_v4_discovery_(executor_pool(), disc_v4_port, node_key, node_url, node_db_.interface()) {
}

Task<void> DiscoveryImpl::run() {
    setup_node_db();

    for (auto& url : peer_urls_) {
        auto& db = node_db_.interface();
        co_await db.upsert_node_address(
            url.public_key(),
            node_db::NodeAddress{url.ip(), url.port_disc(), url.port_rlpx()});
        if (!with_dynamic_discovery_) {
            co_await db.update_last_pong_time(url.public_key(), std::chrono::system_clock::now() + std::chrono::years(1));
        }
    }

    if (with_dynamic_discovery_) {
        co_await disc_v4_discovery_.run();
    }
}

void DiscoveryImpl::setup_node_db() {
    DataDirectory data_dir{data_dir_path_, true};
    node_db_.setup(data_dir.nodes().path());
}

Task<std::vector<EnodeUrl>> DiscoveryImpl::request_peer_urls(
    size_t max_count,
    std::vector<EnodeUrl> exclude_urls) {
    using namespace std::chrono_literals;

    std::vector<node_db::NodeId> exclude_ids;
    for (auto& url : exclude_urls)
        exclude_ids.push_back(url.public_key());

    auto now = std::chrono::system_clock::now();
    node_db::NodeDb::FindPeerCandidatesQuery query{
        /* min_pong_time = */ disc_v4::ping::min_valid_pong_time(now),
        /* max_peer_disconnected_time = */ now - 60s,
        /* max_taken_time = */ now - 30s,
        std::move(exclude_ids),
        max_count,
    };
    auto peer_ids = co_await node_db_.interface().take_peer_candidates(std::move(query), now);

    std::vector<EnodeUrl> peer_urls;
    for (auto& peer_id : peer_ids) {
        auto address = co_await node_db_.interface().find_node_address_v4(peer_id);
        if (!address) {
            address = co_await node_db_.interface().find_node_address_v6(peer_id);
        }
        if (address) {
            EnodeUrl peer_url{
                peer_id,
                address->ip,
                address->port_disc,
                address->port_rlpx,
            };
            peer_urls.push_back(std::move(peer_url));
        }
    }

    if (peer_urls.empty()) {
        disc_v4_discovery_.discover_more_needed();
    }

    co_return peer_urls;
}

bool DiscoveryImpl::is_static_peer_url(const EnodeUrl& peer_url) {
    return std::any_of(peer_urls_.cbegin(), peer_urls_.cend(), [&peer_url](const EnodeUrl& it) {
        return it == peer_url;
    });
}

Task<void> DiscoveryImpl::on_peer_disconnected(EccPublicKey peer_public_key, bool is_useless) {
    auto now = std::chrono::system_clock::now();
    co_await node_db_.interface().update_peer_disconnected_time(peer_public_key, now);
    if (is_useless) {
        co_await node_db_.interface().update_peer_is_useless(peer_public_key, is_useless);
    }
}

Discovery::Discovery(
    std::function<boost::asio::any_io_executor()> executor_pool,
    std::vector<EnodeUrl> peer_urls,
    bool with_dynamic_discovery,
    const std::filesystem::path& data_dir_path,
    std::function<EccKeyPair()> node_key,
    std::function<EnodeUrl()> node_url,
    uint16_t disc_v4_port)
    : p_impl_(std::make_unique<DiscoveryImpl>(
          std::move(executor_pool),
          std::move(peer_urls),
          with_dynamic_discovery,
          data_dir_path,
          std::move(node_key),
          std::move(node_url),
          disc_v4_port)) {}

Discovery::~Discovery() {
    log::Trace("sentry") << "silkworm::sentry::discovery::Discovery::~Discovery";
}

Task<void> Discovery::run() {
    return p_impl_->run();
}

Task<std::vector<EnodeUrl>> Discovery::request_peer_urls(
    size_t max_count,
    std::vector<EnodeUrl> exclude_urls) {
    return p_impl_->request_peer_urls(max_count, std::move(exclude_urls));
}

bool Discovery::is_static_peer_url(const EnodeUrl& peer_url) {
    return p_impl_->is_static_peer_url(peer_url);
}

Task<void> Discovery::on_peer_disconnected(EccPublicKey peer_public_key, bool is_useless) {
    return p_impl_->on_peer_disconnected(std::move(peer_public_key), is_useless);
}

}  // namespace silkworm::sentry::discovery
