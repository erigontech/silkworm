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

#include "auth_ack_message.hpp"

#include <stdexcept>

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/sentry/common/random.hpp>

#include "auth_message_error.hpp"
#include "ecies_cipher.hpp"

namespace silkworm::sentry::rlpx::auth {

AuthAckMessage::AuthAckMessage(
    EccPublicKey initiator_public_key,
    EccPublicKey ephemeral_public_key)
    : initiator_public_key_(std::move(initiator_public_key)),
      ephemeral_public_key_(std::move(ephemeral_public_key)),
      nonce_(random_bytes(32)) {
}

AuthAckMessage::AuthAckMessage(
    ByteView data,
    const EccKeyPair& initiator_key_pair)
    : initiator_public_key_(initiator_key_pair.public_key()),
      ephemeral_public_key_(Bytes{}) {
    init_from_rlp(AuthAckMessage::decrypt_body(data, initiator_key_pair.private_key()));
}

Bytes AuthAckMessage::body_as_rlp() const {
    Bytes data;
    rlp::encode(data, ephemeral_public_key_.serialized(), nonce_, kVersion);
    return data;
}

void AuthAckMessage::init_from_rlp(ByteView data) {
    Bytes public_key_data;
    auto result = rlp::decode(data, rlp::Leftover::kAllow, public_key_data, nonce_);
    if (!result && (result.error() != DecodingError::kUnexpectedListElements)) {
        throw AuthMessageErrorBadRLP(AuthMessageType::kAuthAck, result.error());
    }
    ephemeral_public_key_ = EccPublicKey::deserialize(public_key_data);
}

Bytes AuthAckMessage::serialize_size(size_t body_size) {
    Bytes size(sizeof(uint16_t), 0);
    endian::store_big_u16(size.data(), static_cast<uint16_t>(body_size));
    return size;
}

Bytes AuthAckMessage::decrypt_body(ByteView data, ByteView initiator_private_key) {
    Bytes size = serialize_size(data.size());
    try {
        return EciesCipher::decrypt(data, initiator_private_key, size);
    } catch (const EciesCipherError& ex) {
        throw AuthMessageErrorDecryptFailure(AuthMessageType::kAuthAck, Bytes{data}, ex);
    }
}

Bytes AuthAckMessage::serialize() const {
    Bytes body_rlp = body_as_rlp();
    body_rlp.resize(EciesCipher::round_up_to_block_size(body_rlp.size()));
    size_t body_size = EciesCipher::estimate_encrypted_size(body_rlp.size());

    Bytes size = serialize_size(body_size);
    Bytes body = EciesCipher::encrypt(body_rlp, initiator_public_key_, size);
    return size + body;
}

}  // namespace silkworm::sentry::rlpx::auth
