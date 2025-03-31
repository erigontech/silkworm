// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "message_sender.hpp"

#include <memory>

#include "rlpx/peer.hpp"

namespace silkworm::sentry {

Task<void> MessageSender::run(PeerManager& peer_manager) {
    // loop until receive() throws a cancelled exception
    while (true) {
        auto call = co_await send_message_channel_.receive();

        api::router::SendMessageCall::PeerKeys sent_peer_keys;

        auto sender = [&message = call.message(), &sent_peer_keys, peer_filter = call.peer_filter()](const std::shared_ptr<rlpx::Peer>& peer) {
            auto key_opt = peer->peer_public_key();
            if (key_opt && (!peer_filter.peer_public_key || (key_opt.value() == peer_filter.peer_public_key.value()))) {
                sent_peer_keys.push_back(key_opt.value());
                rlpx::Peer::post_message(peer, message);
            }
        };

        auto max_peers = call.peer_filter().max_peers;
        if (max_peers && (max_peers.value() > 0) && !call.peer_filter().peer_public_key) {
            co_await peer_manager.enumerate_random_peers(max_peers.value(), sender);
        } else {
            co_await peer_manager.enumerate_peers(sender);
        }

        call.set_result(std::move(sent_peer_keys));
    }
}

}  // namespace silkworm::sentry
