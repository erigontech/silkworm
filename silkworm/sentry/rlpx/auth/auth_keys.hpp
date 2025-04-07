// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::rlpx::auth {

struct AuthKeys {
    EccPublicKey peer_public_key;

    EccPublicKey peer_ephemeral_public_key;
    EccKeyPair ephemeral_key_pair;

    Bytes initiator_nonce;
    Bytes recipient_nonce;

    Bytes initiator_first_message_data;
    Bytes recipient_first_message_data;
};

}  // namespace silkworm::sentry::rlpx::auth
