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

#include <algorithm>
#include <iterator>

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/sentry/common/random.hpp>

#include "disc_v4/discovery.hpp"
#include "node_db/node_db_sqlite.hpp"

namespace silkworm::sentry::discovery {

using namespace boost::asio;

class DiscoveryImpl {
  public:
    explicit DiscoveryImpl(
        std::vector<common::EnodeUrl> peer_urls,
        bool with_dynamic_discovery,
        const std::filesystem::path& data_dir_path,
        std::function<common::EccKeyPair()> node_key,
        uint16_t disc_v4_port);

    DiscoveryImpl(const DiscoveryImpl&) = delete;
    DiscoveryImpl& operator=(const DiscoveryImpl&) = delete;

    Task<void> run();

    Task<std::vector<common::EnodeUrl>> request_peer_urls(
        size_t max_count,
        std::vector<common::EnodeUrl> exclude_urls);

    bool is_static_peer_url(const common::EnodeUrl& peer_url);

  private:
    void setup_node_db();

    const std::vector<common::EnodeUrl> peer_urls_;
    bool with_dynamic_discovery_;
    std::filesystem::path data_dir_path_;
    node_db::NodeDbSqlite node_db_;
    disc_v4::Discovery disc_v4_discovery_;
};

DiscoveryImpl::DiscoveryImpl(
    std::vector<common::EnodeUrl> peer_urls,
    bool with_dynamic_discovery,
    const std::filesystem::path& data_dir_path,
    std::function<common::EccKeyPair()> node_key,
    uint16_t disc_v4_port)
    : peer_urls_(std::move(peer_urls)),
      with_dynamic_discovery_(with_dynamic_discovery),
      data_dir_path_(data_dir_path),
      disc_v4_discovery_(disc_v4_port, node_key, node_db_.interface()) {
}

Task<void> DiscoveryImpl::run() {
    setup_node_db();

    if (with_dynamic_discovery_) {
        co_await disc_v4_discovery_.run();
    }
}

void DiscoveryImpl::setup_node_db() {
    DataDirectory data_dir{data_dir_path_, true};
    node_db_.setup(data_dir.nodes().path());
}

template <typename T>
static std::vector<T> exclude_vector_items(
    std::vector<T> items,
    std::vector<T> exclude_items) {
    std::vector<T> remaining_items;
    std::sort(items.begin(), items.end());
    std::sort(exclude_items.begin(), exclude_items.end());
    std::set_difference(
        items.begin(), items.end(),
        exclude_items.begin(), exclude_items.end(),
        std::inserter(remaining_items, remaining_items.begin()));
    return remaining_items;
}

Task<std::vector<common::EnodeUrl>> DiscoveryImpl::request_peer_urls(
    size_t max_count,
    std::vector<common::EnodeUrl> exclude_urls) {
    auto peer_urls = exclude_vector_items(peer_urls_, std::move(exclude_urls));
    co_return common::random_vector_items(peer_urls, max_count);
}

bool DiscoveryImpl::is_static_peer_url(const common::EnodeUrl& peer_url) {
    return std::any_of(peer_urls_.cbegin(), peer_urls_.cend(), [&peer_url](const common::EnodeUrl& it) {
        return it == peer_url;
    });
}

Discovery::Discovery(
    std::vector<common::EnodeUrl> peer_urls,
    bool with_dynamic_discovery,
    const std::filesystem::path& data_dir_path,
    std::function<common::EccKeyPair()> node_key,
    uint16_t disc_v4_port)
    : p_impl_(std::make_unique<DiscoveryImpl>(
          std::move(peer_urls),
          with_dynamic_discovery,
          data_dir_path,
          std::move(node_key),
          disc_v4_port)) {}

Discovery::~Discovery() {
    log::Trace("sentry") << "silkworm::sentry::discovery::Discovery::~Discovery";
}

Task<void> Discovery::run() {
    return p_impl_->run();
}

Task<std::vector<common::EnodeUrl>> Discovery::request_peer_urls(
    size_t max_count,
    std::vector<common::EnodeUrl> exclude_urls) {
    return p_impl_->request_peer_urls(max_count, std::move(exclude_urls));
}

bool Discovery::is_static_peer_url(const common::EnodeUrl& peer_url) {
    return p_impl_->is_static_peer_url(peer_url);
}

}  // namespace silkworm::sentry::discovery
