// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::rlpx::auth {

class EciesCipher {
  public:
    using PublicKey = EccPublicKey;
    using PublicKeyView = const PublicKey&;
    using PrivateKeyView = ByteView;

    struct Message {
        PublicKey ephemeral_public_key;
        Bytes iv;
        Bytes cipher_text;
        Bytes mac;
    };

    static Message encrypt_message(ByteView plain_text, PublicKeyView public_key, ByteView mac_extra_data);
    static Bytes decrypt_message(const Message& message, PrivateKeyView private_key, ByteView mac_extra_data);

    static Bytes encrypt(ByteView plain_text, PublicKeyView public_key, ByteView mac_extra_data);
    static Bytes decrypt(ByteView message_data, PrivateKeyView private_key, ByteView mac_extra_data);

    static Bytes compute_shared_secret(PublicKeyView public_key, PrivateKeyView private_key);
    static size_t round_up_to_block_size(size_t size);
    static size_t estimate_encrypted_size(size_t size);

  private:
    static Bytes serialize_message(const Message& message);
    static Message deserialize_message(ByteView message_data);
};

}  // namespace silkworm::sentry::rlpx::auth
