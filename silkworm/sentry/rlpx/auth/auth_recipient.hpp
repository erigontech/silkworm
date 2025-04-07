// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>

#include "auth_keys.hpp"

namespace silkworm::sentry::rlpx::auth {

class AuthRecipient {
  public:
    explicit AuthRecipient(EccKeyPair recipient_key_pair)
        : recipient_key_pair_(std::move(recipient_key_pair)) {}

    Task<AuthKeys> execute(SocketStream& stream);

  private:
    EccKeyPair recipient_key_pair_;
    EccKeyPair recipient_ephemeral_key_pair_;
};

}  // namespace silkworm::sentry::rlpx::auth
