// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "peer_discovery_feedback.hpp"

#include "rlpx/common/disconnect_reason.hpp"

namespace silkworm::sentry {

Task<void> PeerDiscoveryFeedback::run(
    std::shared_ptr<PeerDiscoveryFeedback> self,
    PeerManager& peer_manager,
    discovery::Discovery& discovery) {
    peer_manager.add_observer(std::weak_ptr(self));

    // loop until a cancelled exception
    while (true) {
        auto [public_key, disconnect_reason] = co_await self->peer_disconnected_events_.receive();
        bool is_useless = disconnect_reason && (*disconnect_reason == rlpx::DisconnectReason::kUselessPeer);
        if (is_useless) {
            co_await discovery.on_peer_useless(*public_key);
        }
        co_await discovery.on_peer_disconnected(*public_key);
    }
}

// PeerManagerObserver
void PeerDiscoveryFeedback::on_peer_added(std::shared_ptr<rlpx::Peer> /*peer*/) {
}

// PeerManagerObserver
void PeerDiscoveryFeedback::on_peer_removed(std::shared_ptr<rlpx::Peer> peer) {
    auto public_key = peer->peer_public_key();
    if (public_key) {
        peer_disconnected_events_.try_send({public_key, peer->disconnect_reason()});
    }
}

// PeerManagerObserver
void PeerDiscoveryFeedback::on_peer_connect_error(const EnodeUrl& peer_url) {
    peer_disconnected_events_.try_send({peer_url.public_key(), rlpx::DisconnectReason::kNetworkError});
}

}  // namespace silkworm::sentry
