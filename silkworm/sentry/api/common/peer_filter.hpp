// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::api {

struct PeerFilter {
    std::optional<size_t> max_peers;
    std::optional<sentry::EccPublicKey> peer_public_key;

    static PeerFilter with_max_peers(size_t max_peers) {
        return {{max_peers}, std::nullopt};
    }

    static PeerFilter with_peer_public_key(sentry::EccPublicKey public_key) {
        return {std::nullopt, {std::move(public_key)}};
    }
};

}  // namespace silkworm::sentry::api
