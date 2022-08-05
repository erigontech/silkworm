/*
Copyright 2020-2022 The Silkworm Authors

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

#include "ecc_key_pair.hpp"
#include <array>
#include <silkworm/sentry/common/random.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/common/secp256k1_context.hpp>

namespace silkworm::sentry::common {

EccKeyPair::EccKeyPair() {
    SecP256K1Context ctx;
    do {
        private_key_ = common::random_bytes(32);
    } while (!ctx.verify_private_key_data(private_key_));
}

EccKeyPair::EccKeyPair(Bytes data) : private_key_(std::move(data)) {
    SecP256K1Context ctx;

    if (!ctx.verify_private_key_data(private_key_)) {
        throw std::invalid_argument("Invalid node key");
    }
}

EccKeyPair::EccKeyPair(ByteView data) : EccKeyPair(Bytes(data)) {
}

Bytes EccKeyPair::public_key() const {
    SecP256K1Context ctx{/* allow_verify = */ false, /* allow_sign = */ true};
    secp256k1_pubkey public_key;
    bool ok = ctx.create_public_key(&public_key, private_key_);
    if (!ok) {
        throw std::runtime_error("Failed to create a corresponding public key");
    }
    return {public_key.data, sizeof(public_key.data)};
}

std::string EccKeyPair::public_key_hex() const {
    return ::silkworm::to_hex(public_key());
}

std::string EccKeyPair::private_key_hex() const {
    return ::silkworm::to_hex(private_key_);
}

}  // namespace silkworm::sentry::common
