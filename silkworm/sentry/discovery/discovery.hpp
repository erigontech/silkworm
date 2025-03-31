// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/concurrency/executor_pool.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/enode_url.hpp>
#include <silkworm/sentry/discovery/enr/enr_record.hpp>

namespace silkworm::sentry::discovery {

class DiscoveryImpl;

class Discovery {
  public:
    explicit Discovery(
        concurrency::ExecutorPool& executor_pool,
        std::vector<EnodeUrl> peer_urls,
        bool with_dynamic_discovery,
        const std::filesystem::path& data_dir_path,
        uint64_t network_id,
        std::function<EccKeyPair()> node_key,
        std::function<EnodeUrl()> node_url,
        std::function<enr::EnrRecord()> node_record,
        std::vector<EnodeUrl> bootnodes,
        uint16_t disc_v4_port);
    ~Discovery();

    Discovery(const Discovery&) = delete;
    Discovery& operator=(const Discovery&) = delete;

    Task<void> run();

    struct PeerCandidate {
        EnodeUrl url;
        std::optional<Bytes> eth1_fork_id_data;
    };

    Task<std::vector<PeerCandidate>> request_peer_candidates(
        size_t max_count,
        std::vector<EnodeUrl> exclude_urls);

    bool is_static_peer_url(const EnodeUrl& peer_url);

    Task<void> on_peer_useless(EccPublicKey peer_public_key);
    Task<void> on_peer_disconnected(EccPublicKey peer_public_key);

  private:
    std::unique_ptr<DiscoveryImpl> p_impl_;
};

}  // namespace silkworm::sentry::discovery
