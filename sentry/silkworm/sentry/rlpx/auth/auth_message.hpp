/*
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#pragma once

#include <silkworm/common/base.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::rlpx::auth {

class AuthMessage {
  public:
    AuthMessage(
        const common::EccKeyPair& initiator_key_pair,
        common::EccPublicKey recipient_public_key,
        const common::EccKeyPair& ephemeral_key_pair);
    AuthMessage(ByteView data, const common::EccKeyPair& recipient_key_pair);

    [[nodiscard]] Bytes serialize() const;

    [[nodiscard]] const common::EccPublicKey& initiator_public_key() const {
        return initiator_public_key_;
    }

    [[nodiscard]] const common::EccPublicKey& ephemeral_public_key() const {
        return ephemeral_public_key_;
    }

    [[nodiscard]] ByteView nonce() const { return nonce_; }

  private:
    [[nodiscard]] Bytes body_as_rlp() const;
    void init_from_rlp(ByteView data);

    static Bytes serialize_size(size_t body_size);
    static Bytes decrypt_body(ByteView data, ByteView recipient_private_key);

    common::EccPublicKey initiator_public_key_;
    common::EccPublicKey recipient_public_key_;
    common::EccPublicKey ephemeral_public_key_;
    Bytes nonce_;
    Bytes signature_;
    static const uint8_t version;
};

}  // namespace silkworm::sentry::rlpx::auth
