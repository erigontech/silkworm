// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ecdsa.h"

#include <string.h>

#include <ethash/keccak.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>

//! \brief Tries recover public key used for message signing.
static bool recover(uint8_t public_key[65], const uint8_t message[32], const uint8_t signature[64], uint8_t recovery_id,
                    const secp256k1_context* context) {
    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(context, &sig, signature, recovery_id)) {
        return false;
    }

    secp256k1_pubkey pub_key;
    if (!secp256k1_ecdsa_recover(context, &pub_key, &sig, message)) {
        return false;
    }

    size_t key_len = 65;
    return secp256k1_ec_pubkey_serialize(context, public_key, &key_len, &pub_key, SECP256K1_EC_UNCOMPRESSED);
}

//! Tries extract address from recovered public key
//! \param [in] public_key: The recovered public key
//! \return Whether the recovery has succeeded.
static bool public_key_to_address(uint8_t out[20], const uint8_t public_key[65]) {
    if (public_key[0] != 4u) {
        return false;
    }
    // Ignore first byte of public key
    const union ethash_hash256 key_hash = ethash_keccak256(public_key + 1, 64);
    memcpy(out, &key_hash.bytes[12], 20);
    return true;
}

bool silkworm_recover_address(uint8_t out[20], const uint8_t message[32], const uint8_t signature[64],
                              uint8_t recovery_id, const secp256k1_context* context) {
    uint8_t public_key[65];
    if (!recover(public_key, message, signature, recovery_id, context)) {
        return false;
    }
    return public_key_to_address(out, public_key);
}
