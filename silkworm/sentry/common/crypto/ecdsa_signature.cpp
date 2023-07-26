/*
   Copyright 2023 The Silkworm Authors

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

#include "ecdsa_signature.hpp"

#include <stdexcept>

#include <silkworm/infra/common/secp256k1_context.hpp>

namespace silkworm::sentry::crypto::ecdsa_signature {

Bytes sign(ByteView data, ByteView private_key) {
    SecP256K1Context ctx{/* allow_verify = */ false, /* allow_sign = */ true};
    secp256k1_ecdsa_recoverable_signature signature;
    bool ok = ctx.sign_recoverable(&signature, data, private_key);
    if (!ok) {
        throw std::runtime_error("rlpx::auth::sign failed to sign an AuthMessage");
    }

    auto [signature_data, recovery_id] = ctx.serialize_recoverable_signature(&signature);
    signature_data.push_back(recovery_id);
    return signature_data;
}

EccPublicKey recover_and_verify(ByteView data, ByteView signature_and_recovery_id) {
    if (signature_and_recovery_id.empty()) {
        throw std::runtime_error("rlpx::auth::recover_and_verify: AuthMessage signature is empty");
    }
    uint8_t recovery_id = signature_and_recovery_id.back();
    ByteView signature_data = {signature_and_recovery_id.data(), signature_and_recovery_id.size() - 1};

    SecP256K1Context ctx;
    secp256k1_ecdsa_recoverable_signature signature;
    bool ok = ctx.parse_recoverable_signature(&signature, signature_data, recovery_id);
    if (!ok) {
        throw std::runtime_error("rlpx::auth::recover_and_verify: failed to parse an AuthMessage signature");
    }

    secp256k1_pubkey public_key;
    ok = ctx.recover_signature_public_key(&public_key, &signature, data);
    if (!ok) {
        throw std::runtime_error("rlpx::auth::recover_and_verify: failed to recover a public key from an AuthMessage signature");
    }
    return EccPublicKey{Bytes{public_key.data, sizeof(public_key.data)}};
}

}  // namespace silkworm::sentry::crypto::ecdsa_signature
