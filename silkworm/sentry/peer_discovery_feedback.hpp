// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <optional>
#include <utility>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/discovery/discovery.hpp>
#include <silkworm/sentry/rlpx/common/disconnect_reason.hpp>

#include "peer_manager.hpp"
#include "peer_manager_observer.hpp"

namespace silkworm::sentry {

class PeerDiscoveryFeedback : public PeerManagerObserver {
  public:
    PeerDiscoveryFeedback(const boost::asio::any_io_executor& executor, size_t max_peers)
        : peer_disconnected_events_(executor, max_peers) {}

    static Task<void> run(
        std::shared_ptr<PeerDiscoveryFeedback> self,
        PeerManager& peer_manager,
        discovery::Discovery& discovery);

  private:
    // PeerManagerObserver
    void on_peer_added(std::shared_ptr<rlpx::Peer> peer) override;
    void on_peer_removed(std::shared_ptr<rlpx::Peer> peer) override;
    void on_peer_connect_error(const EnodeUrl& peer_url) override;

    struct PeerDisconnectedEvent {
        std::optional<EccPublicKey> peer_public_key;
        std::optional<rlpx::DisconnectReason> disconnect_reason;
    };

    concurrency::Channel<PeerDisconnectedEvent> peer_disconnected_events_;
};

}  // namespace silkworm::sentry
