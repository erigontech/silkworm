// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "discovery.hpp"

#include <chrono>

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>

#include "bootnodes.hpp"
#include "common/node_address.hpp"
#include "disc_v4/common/node_distance.hpp"
#include "disc_v4/discovery.hpp"
#include "disc_v4/ping/ping_check.hpp"
#include "node_db/node_db_sqlite.hpp"

namespace silkworm::sentry::discovery {

using namespace boost::asio;

class DiscoveryImpl {
  public:
    explicit DiscoveryImpl(
        concurrency::ExecutorPool& executor_pool,
        std::vector<EnodeUrl> peer_urls,
        bool with_dynamic_discovery,
        std::filesystem::path data_dir_path,
        uint64_t network_id,
        std::function<EccKeyPair()> node_key,
        std::function<EnodeUrl()> node_url,
        std::function<enr::EnrRecord()> node_record,
        std::vector<EnodeUrl> bootnodes,
        uint16_t disc_v4_port);

    DiscoveryImpl(const DiscoveryImpl&) = delete;
    DiscoveryImpl& operator=(const DiscoveryImpl&) = delete;

    Task<void> run();

    Task<std::vector<Discovery::PeerCandidate>> request_peer_candidates(
        size_t max_count,
        std::vector<EnodeUrl> exclude_urls);

    bool is_static_peer_url(const EnodeUrl& peer_url);

    Task<void> on_peer_useless(EccPublicKey peer_public_key);
    Task<void> on_peer_disconnected(EccPublicKey peer_public_key);

  private:
    void setup_node_db();

    const std::vector<EnodeUrl> peer_urls_;
    bool with_dynamic_discovery_;
    std::filesystem::path data_dir_path_;
    std::function<EccPublicKey()> node_id_;
    uint64_t network_id_;
    node_db::NodeDbSqlite node_db_;
    std::vector<EnodeUrl> bootnodes_;
    disc_v4::Discovery disc_v4_discovery_;
};

DiscoveryImpl::DiscoveryImpl(
    concurrency::ExecutorPool& executor_pool,
    std::vector<EnodeUrl> peer_urls,
    bool with_dynamic_discovery,
    std::filesystem::path data_dir_path,
    uint64_t network_id,
    std::function<EccKeyPair()> node_key,  // NOLINT(performance-unnecessary-value-param)
    std::function<EnodeUrl()> node_url,
    std::function<enr::EnrRecord()> node_record,
    std::vector<EnodeUrl> bootnodes,
    uint16_t disc_v4_port)
    : peer_urls_(std::move(peer_urls)),
      with_dynamic_discovery_(with_dynamic_discovery),
      data_dir_path_(std::move(data_dir_path)),
      node_id_([node_key] { return node_key().public_key(); }),
      network_id_(network_id),
      node_db_(executor_pool.any_executor()),
      bootnodes_(std::move(bootnodes)),
      disc_v4_discovery_(executor_pool.any_executor(), disc_v4_port, node_key, std::move(node_url), std::move(node_record), node_db_.interface()) {
}

Task<void> DiscoveryImpl::run() {
    setup_node_db();

    auto local_node_id = node_id_();

    for (auto& url : peer_urls_) {
        auto& node_id = url.public_key();
        if (node_id == local_node_id) {
            SILK_WARN_M("sentry") << "Discovery: ignoring the local node in the static peers list, please remove " << url.to_string();
            continue;
        }

        auto& db = node_db_.interface();
        co_await db.upsert_node_address(
            node_id,
            NodeAddress{url.ip(), url.port_disc(), url.port_rlpx()});
        co_await db.update_distance(node_id, disc_v4::node_distance(node_id, local_node_id));
        if (!with_dynamic_discovery_) {
            co_await db.update_last_pong_time(node_id, std::chrono::system_clock::now() + std::chrono::years(1));
        }
    }

    if (with_dynamic_discovery_) {
        std::span<EnodeUrl> bootnode_urls{bootnodes_.data(), bootnodes_.size()};
        if (bootnode_urls.empty()) {
            bootnode_urls = bootnodes(network_id_);
        }

        for (auto& url : bootnode_urls) {
            auto& node_id = url.public_key();
            if (node_id == local_node_id) {
                SILK_WARN_M("sentry") << "Discovery: ignoring the local node in the bootnodes list, please remove " << url.to_string();
                continue;
            }

            auto& db = node_db_.interface();
            co_await db.upsert_node_address(
                node_id,
                NodeAddress{url.ip(), url.port_disc(), url.port_rlpx()});
            co_await db.update_distance(node_id, disc_v4::node_distance(node_id, local_node_id));
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

Task<std::vector<Discovery::PeerCandidate>> DiscoveryImpl::request_peer_candidates(
    size_t max_count,
    std::vector<EnodeUrl> exclude_urls) {
    using namespace std::chrono_literals;

    std::vector<node_db::NodeId> exclude_ids;
    exclude_ids.reserve(exclude_urls.size());
    for (auto& url : exclude_urls) {
        exclude_ids.push_back(url.public_key());
    }

    auto now = std::chrono::system_clock::now();
    node_db::NodeDb::FindPeerCandidatesQuery query{
        /* min_pong_time = */ disc_v4::ping::min_valid_pong_time(now),
        /* max_peer_disconnected_time = */ now - 60s,
        /* max_taken_time = */ now - 30s,
        std::move(exclude_ids),
        max_count,
    };
    auto peer_ids = co_await node_db_.interface().take_peer_candidates(std::move(query), now);

    std::vector<Discovery::PeerCandidate> candidates;
    for (auto& peer_id : peer_ids) {
        auto address = co_await node_db_.interface().find_node_address(peer_id);
        if (address) {
            auto eth1_fork_id_data = co_await node_db_.interface().find_eth1_fork_id(peer_id);

            EnodeUrl peer_url{
                peer_id,
                address->ip,
                address->port_disc,
                address->port_rlpx,
            };
            Discovery::PeerCandidate candidate{
                std::move(peer_url),
                std::move(eth1_fork_id_data),
            };
            candidates.push_back(std::move(candidate));
        }
    }

    if (candidates.empty()) {
        disc_v4_discovery_.discover_more_needed();
    }

    co_return candidates;
}

bool DiscoveryImpl::is_static_peer_url(const EnodeUrl& peer_url) {
    return std::any_of(peer_urls_.cbegin(), peer_urls_.cend(), [&peer_url](const EnodeUrl& it) {
        return it == peer_url;
    });
}

Task<void> DiscoveryImpl::on_peer_useless(EccPublicKey peer_public_key) {
    co_await node_db_.interface().update_peer_is_useless(peer_public_key, true);
}

Task<void> DiscoveryImpl::on_peer_disconnected(EccPublicKey peer_public_key) {
    auto now = std::chrono::system_clock::now();
    co_await node_db_.interface().update_peer_disconnected_time(peer_public_key, now);
}

Discovery::Discovery(
    concurrency::ExecutorPool& executor_pool,
    std::vector<EnodeUrl> peer_urls,
    bool with_dynamic_discovery,
    const std::filesystem::path& data_dir_path,
    uint64_t network_id,
    std::function<EccKeyPair()> node_key,
    std::function<EnodeUrl()> node_url,
    std::function<enr::EnrRecord()> node_record,
    std::vector<EnodeUrl> bootnodes,
    uint16_t disc_v4_port)
    : p_impl_(std::make_unique<DiscoveryImpl>(
          executor_pool,
          std::move(peer_urls),
          with_dynamic_discovery,
          data_dir_path,
          network_id,
          std::move(node_key),
          std::move(node_url),
          std::move(node_record),
          std::move(bootnodes),
          disc_v4_port)) {}

Discovery::~Discovery() {
    SILK_TRACE_M("sentry") << "silkworm::sentry::discovery::Discovery::~Discovery";
}

Task<void> Discovery::run() {
    try {
        return p_impl_->run();
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::system::errc::operation_canceled) {
            SILK_DEBUG_M("sentry") << "Discovery::run unexpected end [operation_canceled]";
        } else {
            SILK_CRIT_M("sentry") << "Discovery::run unexpected end [" + std::string{se.what()} + "]";
        }
        throw se;
    }
}

Task<std::vector<Discovery::PeerCandidate>> Discovery::request_peer_candidates(
    size_t max_count,
    std::vector<EnodeUrl> exclude_urls) {
    return p_impl_->request_peer_candidates(max_count, std::move(exclude_urls));
}

bool Discovery::is_static_peer_url(const EnodeUrl& peer_url) {
    return p_impl_->is_static_peer_url(peer_url);
}

Task<void> Discovery::on_peer_useless(EccPublicKey peer_public_key) {
    return p_impl_->on_peer_useless(std::move(peer_public_key));
}

Task<void> Discovery::on_peer_disconnected(EccPublicKey peer_public_key) {
    return p_impl_->on_peer_disconnected(std::move(peer_public_key));
}

}  // namespace silkworm::sentry::discovery
