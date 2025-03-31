// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>

#include "auth_keys.hpp"

namespace silkworm::sentry::rlpx::auth {

class AuthInitiator {
  public:
    AuthInitiator(EccKeyPair initiator_key_pair, EccPublicKey recipient_public_key)
        : initiator_key_pair_(std::move(initiator_key_pair)),
          recipient_public_key_(std::move(recipient_public_key)) {}

    Task<AuthKeys> execute(SocketStream& stream);

  private:
    EccKeyPair initiator_key_pair_;
    EccPublicKey recipient_public_key_;
    EccKeyPair initiator_ephemeral_key_pair_;
};

}  // namespace silkworm::sentry::rlpx::auth
