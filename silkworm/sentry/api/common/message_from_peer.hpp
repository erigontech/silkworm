// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::api {

struct MessageFromPeer {
    sentry::Message message;
    std::optional<sentry::EccPublicKey> peer_public_key;
};

}  // namespace silkworm::sentry::api
