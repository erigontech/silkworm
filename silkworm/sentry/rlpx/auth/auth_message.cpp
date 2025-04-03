// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "auth_message.hpp"

#include <stdexcept>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/sentry/common/crypto/ecdsa_signature.hpp>
#include <silkworm/sentry/common/crypto/xor.hpp>
#include <silkworm/sentry/common/random.hpp>

#include "auth_message_error.hpp"
#include "ecies_cipher.hpp"

namespace silkworm::sentry::rlpx::auth {

using namespace silkworm::sentry::crypto::ecdsa_signature;

AuthMessage::AuthMessage(
    const EccKeyPair& initiator_key_pair,
    EccPublicKey recipient_public_key,
    const EccKeyPair& ephemeral_key_pair)
    : initiator_public_key_(initiator_key_pair.public_key()),
      recipient_public_key_(std::move(recipient_public_key)),
      ephemeral_public_key_(ephemeral_key_pair.public_key()) {
    Bytes shared_secret = EciesCipher::compute_shared_secret(recipient_public_key_, initiator_key_pair.private_key());

    nonce_ = random_bytes(shared_secret.size());

    // shared_secret ^= nonce_
    crypto::xor_bytes(shared_secret, nonce_);

    signature_ = sign_recoverable(shared_secret, ephemeral_key_pair.private_key());
}

AuthMessage::AuthMessage(ByteView data, const EccKeyPair& recipient_key_pair)
    : initiator_public_key_(Bytes{}),
      recipient_public_key_(recipient_key_pair.public_key()),
      ephemeral_public_key_(Bytes{}) {
    auto recipient_private_key = recipient_key_pair.private_key();
    init_from_rlp(AuthMessage::decrypt_body(data, recipient_private_key));

    Bytes shared_secret = EciesCipher::compute_shared_secret(initiator_public_key_, recipient_private_key);

    if (shared_secret.size() != nonce_.size())
        throw std::runtime_error("rlpx::auth::AuthMessage: invalid nonce size");

    // shared_secret ^= nonce_
    crypto::xor_bytes(shared_secret, nonce_);

    ephemeral_public_key_ = verify_and_recover(shared_secret, signature_);
}

Bytes AuthMessage::body_as_rlp() const {
    Bytes data;
    rlp::encode(data, signature_, initiator_public_key_.serialized(), nonce_, kVersion);
    return data;
}

void AuthMessage::init_from_rlp(ByteView data) {
    Bytes public_key_data;
    auto result = rlp::decode(data, rlp::Leftover::kAllow, signature_, public_key_data, nonce_);
    if (!result && (result.error() != DecodingError::kUnexpectedListElements)) {
        throw AuthMessageErrorBadRLP(AuthMessageType::kAuth, result.error());
    }
    initiator_public_key_ = EccPublicKey::deserialize(public_key_data);
}

Bytes AuthMessage::serialize_size(size_t body_size) {
    Bytes size(sizeof(uint16_t), 0);
    endian::store_big_u16(size.data(), static_cast<uint16_t>(body_size));
    return size;
}

Bytes AuthMessage::decrypt_body(ByteView data, ByteView recipient_private_key) {
    Bytes size = serialize_size(data.size());
    try {
        return EciesCipher::decrypt(data, recipient_private_key, size);
    } catch (const EciesCipherError& ex) {
        throw AuthMessageErrorDecryptFailure(AuthMessageType::kAuth, Bytes{data}, ex);
    }
}

Bytes AuthMessage::serialize() const {
    Bytes body_rlp = body_as_rlp();
    body_rlp.resize(EciesCipher::round_up_to_block_size(body_rlp.size()));
    size_t body_size = EciesCipher::estimate_encrypted_size(body_rlp.size());

    Bytes size = serialize_size(body_size);
    Bytes body = EciesCipher::encrypt(body_rlp, recipient_public_key_, size);
    return size + body;
}

}  // namespace silkworm::sentry::rlpx::auth
