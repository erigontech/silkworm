// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::rlpx::auth {

class AuthMessage {
  public:
    AuthMessage(
        const EccKeyPair& initiator_key_pair,
        EccPublicKey recipient_public_key,
        const EccKeyPair& ephemeral_key_pair);
    AuthMessage(ByteView data, const EccKeyPair& recipient_key_pair);

    Bytes serialize() const;

    const EccPublicKey& initiator_public_key() const {
        return initiator_public_key_;
    }

    const EccPublicKey& ephemeral_public_key() const {
        return ephemeral_public_key_;
    }

    ByteView nonce() const { return nonce_; }

  private:
    Bytes body_as_rlp() const;
    void init_from_rlp(ByteView data);

    static Bytes serialize_size(size_t body_size);
    static Bytes decrypt_body(ByteView data, ByteView recipient_private_key);

    EccPublicKey initiator_public_key_;
    EccPublicKey recipient_public_key_;
    EccPublicKey ephemeral_public_key_;
    Bytes nonce_;
    Bytes signature_;
    static constexpr uint8_t kVersion{4};
};

}  // namespace silkworm::sentry::rlpx::auth
