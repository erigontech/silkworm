// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::api {

enum class PeerEventId {
    kAdded,
    kRemoved,
};

struct PeerEvent {
    std::optional<sentry::EccPublicKey> peer_public_key;
    PeerEventId event_id{};
};

}  // namespace silkworm::sentry::api
