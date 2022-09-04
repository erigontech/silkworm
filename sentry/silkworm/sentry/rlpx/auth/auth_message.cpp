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

#include "auth_message.hpp"

#include <silkworm/common/endian.hpp>
#include <silkworm/common/secp256k1_context.hpp>
#include <silkworm/rlp/decode.hpp>
#include <silkworm/rlp/encode_vector.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/random.hpp>
#include <silkworm/sentry/rlpx/crypto/xor.hpp>

#include "ecies_cipher.hpp"

namespace silkworm::sentry::rlpx::auth {

static Bytes sign(ByteView data, ByteView private_key) {
    SecP256K1Context ctx{/* allow_verify = */ false, /* allow_sign = */ true};
    secp256k1_ecdsa_recoverable_signature signature;
    bool ok = ctx.sign_recoverable(&signature, data, private_key);
    if (!ok) {
        throw std::runtime_error("Failed to sign an AuthMessage");
    }

    auto [signature_data, recovery_id] = ctx.serialize_recoverable_signature(&signature);
    signature_data.push_back(recovery_id);
    return signature_data;
}

static common::EccPublicKey recover_and_verify(ByteView data, ByteView signature_and_recovery_id) {
    if (signature_and_recovery_id.empty()) {
        throw std::runtime_error("AuthMessage signature is empty");
    }
    uint8_t recovery_id = signature_and_recovery_id.back();
    ByteView signature_data = {signature_and_recovery_id.data(), signature_and_recovery_id.size() - 1};

    SecP256K1Context ctx;
    secp256k1_ecdsa_recoverable_signature signature;
    bool ok = ctx.parse_recoverable_signature(&signature, signature_data, recovery_id);
    if (!ok) {
        throw std::runtime_error("Failed to parse an AuthMessage signature");
    }

    secp256k1_pubkey public_key;
    ok = ctx.recover_signature_public_key(&public_key, &signature, data);
    if (!ok) {
        throw std::runtime_error("Failed to recover a public key from an AuthMessage signature");
    }
    return common::EccPublicKey{Bytes{public_key.data, sizeof(public_key.data)}};
}

const uint8_t AuthMessage::version = 4;

AuthMessage::AuthMessage(
    const common::EccKeyPair& initiator_key_pair,
    common::EccPublicKey recipient_public_key,
    const common::EccKeyPair& ephemeral_key_pair)
    : initiator_public_key_(initiator_key_pair.public_key()),
      recipient_public_key_(std::move(recipient_public_key)),
      ephemeral_public_key_(ephemeral_key_pair.public_key()) {
    Bytes shared_secret = EciesCipher::compute_shared_secret(recipient_public_key_, initiator_key_pair.private_key());

    nonce_ = common::random_bytes(shared_secret.size());

    // shared_secret ^= nonce_
    crypto::xor_bytes(shared_secret, nonce_);

    signature_ = sign(shared_secret, ephemeral_key_pair.private_key());
}

AuthMessage::AuthMessage(ByteView data, const common::EccKeyPair& recipient_key_pair)
    : initiator_public_key_(Bytes{}),
      recipient_public_key_(recipient_key_pair.public_key()),
      ephemeral_public_key_(Bytes{}) {
    auto recipient_private_key = recipient_key_pair.private_key();
    init_from_rlp(AuthMessage::decrypt_body(data, recipient_private_key));

    Bytes shared_secret = EciesCipher::compute_shared_secret(initiator_public_key_, recipient_private_key);

    if (shared_secret.size() != nonce_.size())
        throw std::runtime_error("AuthMessage: invalid nonce size");

    // shared_secret ^= nonce_
    crypto::xor_bytes(shared_secret, nonce_);

    ephemeral_public_key_ = recover_and_verify(shared_secret, signature_);
}

Bytes AuthMessage::body_as_rlp() const {
    Bytes data;
    rlp::encode(data, signature_, initiator_public_key_.serialized(), nonce_, version);
    return data;
}

void AuthMessage::init_from_rlp(ByteView data) {
    Bytes public_key_data;
    auto err = rlp::decode(data, signature_, public_key_data, nonce_);
    if (err != DecodingResult::kOk) {
        throw std::runtime_error("Failed to decode AuthMessage RLP");
    }
    initiator_public_key_ = common::EccPublicKey::deserialize(public_key_data);
}

Bytes AuthMessage::serialize_size(size_t body_size) {
    Bytes size(sizeof(uint16_t), 0);
    endian::store_big_u16(size.data(), static_cast<uint16_t>(body_size));
    return size;
}

Bytes AuthMessage::decrypt_body(ByteView data, ByteView recipient_private_key) {
    Bytes size = serialize_size(data.size());
    return EciesCipher::decrypt(data, recipient_private_key, size);
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
