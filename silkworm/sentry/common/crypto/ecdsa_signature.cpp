// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ecdsa_signature.hpp"

#include <stdexcept>

#include <silkworm/infra/common/secp256k1_context.hpp>

namespace silkworm::sentry::crypto::ecdsa_signature {

Bytes sign_recoverable(ByteView data_hash, ByteView private_key) {
    SecP256K1Context ctx{/* allow_verify = */ false, /* allow_sign = */ true};
    secp256k1_ecdsa_recoverable_signature signature;
    bool ok = ctx.sign_recoverable(&signature, data_hash, private_key);
    if (!ok) {
        throw std::runtime_error("ecdsa_signature::sign_recoverable failed");
    }

    auto [signature_data, recovery_id] = ctx.serialize_recoverable_signature(&signature);
    signature_data.push_back(recovery_id);
    return signature_data;
}

Bytes sign(ByteView data_hash, ByteView private_key) {
    SecP256K1Context ctx{/* allow_verify = */ false, /* allow_sign = */ true};
    secp256k1_ecdsa_signature signature;
    bool ok = ctx.sign(&signature, data_hash, private_key);
    if (!ok) {
        throw std::runtime_error("ecdsa_signature::sign failed");
    }

    return ctx.serialize_signature(&signature);
}

EccPublicKey verify_and_recover(ByteView data_hash, ByteView signature_and_recovery_id) {
    if (signature_and_recovery_id.empty()) {
        throw std::runtime_error("ecdsa_signature::verify_and_recover: signature is empty");
    }
    uint8_t recovery_id = signature_and_recovery_id.back();
    ByteView signature_data = {signature_and_recovery_id.data(), signature_and_recovery_id.size() - 1};

    SecP256K1Context ctx;
    secp256k1_ecdsa_recoverable_signature signature;
    bool ok = ctx.parse_recoverable_signature(&signature, signature_data, recovery_id);
    if (!ok) {
        throw std::runtime_error("ecdsa_signature::verify_and_recover: failed to parse a signature");
    }

    secp256k1_pubkey public_key;
    ok = ctx.recover_signature_public_key(&public_key, &signature, data_hash);
    if (!ok) {
        throw std::runtime_error("ecdsa_signature::verify_and_recover: failed to recover a public key from a signature");
    }
    return EccPublicKey{Bytes{public_key.data, sizeof(public_key.data)}};
}

bool verify(ByteView data_hash, ByteView signature_data, const EccPublicKey& public_key1) {
    SecP256K1Context ctx;
    secp256k1_ecdsa_signature signature;
    bool ok = ctx.parse_signature(&signature, signature_data);
    if (!ok) {
        throw std::runtime_error("ecdsa_signature::verify: failed to parse a signature");
    }

    secp256k1_pubkey public_key;
    memcpy(public_key.data, public_key1.data().data(), sizeof(public_key.data));

    return ctx.verify_signature(&signature, data_hash, &public_key);
}

}  // namespace silkworm::sentry::crypto::ecdsa_signature
