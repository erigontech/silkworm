// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "secp256k1_context.hpp"

#include <secp256k1_ecdh.h>

namespace silkworm {

const size_t SecP256K1Context::kPublicKeySizeCompressed = 33;
const size_t SecP256K1Context::kPublicKeySizeUncompressed = 65;

Bytes SecP256K1Context::serialize_public_key(const secp256k1_pubkey* public_key, bool is_compressed) const {
    size_t data_size = is_compressed ? kPublicKeySizeCompressed : kPublicKeySizeUncompressed;
    Bytes data(data_size, 0);
    unsigned int flags = is_compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
    secp256k1_ec_pubkey_serialize(context_, data.data(), &data_size, public_key, flags);
    data.resize(data_size);
    return data;
}

unsigned int SecP256K1Context::flags(bool allow_verify, bool allow_sign) {
    unsigned int value = SECP256K1_CONTEXT_NONE;
    if (allow_verify) {
        value |= SECP256K1_CONTEXT_VERIFY;
    }
    if (allow_sign) {
        value |= SECP256K1_CONTEXT_SIGN;
    }
    return value;
}

// degenerate hash function that just copies the given X value
// see: ecies.GenerateShared in Erigon
static int ecdh_hash_function_copy_x(
    unsigned char* output,
    const unsigned char* x32,
    const unsigned char*,
    void*) {
    memcpy(output, x32, 32);
    return 1;
};

bool SecP256K1Context::compute_ecdh_secret(
    Bytes& shared_secret,
    const secp256k1_pubkey* public_key,
    const ByteView& private_key) const {
    return secp256k1_ecdh(context_, shared_secret.data(), public_key, private_key.data(), ecdh_hash_function_copy_x, nullptr);
}

}  // namespace silkworm
