// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/sentry/common/enode_url.hpp>
#include <silkworm/sentry/rlpx/peer.hpp>

namespace silkworm::sentry {

struct PeerManagerObserver {
    virtual ~PeerManagerObserver() = default;
    virtual void on_peer_added(std::shared_ptr<silkworm::sentry::rlpx::Peer> peer) = 0;
    virtual void on_peer_removed(std::shared_ptr<silkworm::sentry::rlpx::Peer> peer) = 0;
    virtual void on_peer_connect_error(const EnodeUrl& peer_url) = 0;
};

}  // namespace silkworm::sentry
