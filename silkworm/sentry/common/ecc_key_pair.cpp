// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ecc_key_pair.hpp"

#include <stdexcept>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/secp256k1_context.hpp>

#include "random.hpp"

namespace silkworm::sentry {

EccKeyPair::EccKeyPair() {
    SecP256K1Context ctx;
    do {
        private_key_ = random_bytes(32);
    } while (!ctx.verify_private_key_data(private_key_));
}

EccKeyPair::EccKeyPair(Bytes private_key_data) : private_key_(std::move(private_key_data)) {
    SecP256K1Context ctx;

    if (!ctx.verify_private_key_data(private_key_)) {
        throw std::invalid_argument("Invalid node key");
    }
}

EccPublicKey EccKeyPair::public_key() const {
    SecP256K1Context ctx{/* allow_verify = */ false, /* allow_sign = */ true};
    secp256k1_pubkey public_key;
    bool ok = ctx.create_public_key(&public_key, private_key_);
    if (!ok) {
        throw std::runtime_error("EccKeyPair::public_key failed to create a corresponding public key");
    }
    return EccPublicKey(Bytes{public_key.data, sizeof(public_key.data)});
}

std::string EccKeyPair::private_key_hex() const {
    return ::silkworm::to_hex(private_key_);
}

}  // namespace silkworm::sentry
