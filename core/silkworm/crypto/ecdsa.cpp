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

#include "ecdsa.hpp"

#include <optional>

#include <ethash/hash_types.hpp>
#include <ethash/keccak.hpp>
#include <secp256k1_recovery.h>

#include <silkworm/common/base.hpp>

namespace silkworm::ecdsa {

secp256k1_context* create_context(uint32_t flags) { return secp256k1_context_create(flags); }

//! \brief Tries recover public key used for message signing.
//! \return An optional Bytes. Should it has no value the recovery has failed
//! This is different from recover_address as the whole 64 bytes are returned.
std::optional<Bytes> recover(const uint8_t message[32], const uint8_t signature[64], bool odd_y_parity,
                             secp256k1_context* context) noexcept {
    static secp256k1_context* static_context{create_context()};
    if (!context) {
        context = static_context;
    }

    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(context, &sig, &signature[0], odd_y_parity)) {
        return std::nullopt;
    }

    secp256k1_pubkey pub_key;
    if (!secp256k1_ecdsa_recover(context, &pub_key, &sig, &message[0])) {
        return std::nullopt;
    }

    size_t kOutLen{65};
    Bytes out(kOutLen, '\0');
    secp256k1_ec_pubkey_serialize(context, &out[0], &kOutLen, &pub_key, SECP256K1_EC_UNCOMPRESSED);
    return out;
}

//! Tries extract address from recovered public key
//! \param [in] public_key: The recovered public key
//! \return Whether the recovery has succeeded.
static bool public_key_to_address(uint8_t* out, const Bytes& public_key) noexcept {
    if (public_key.length() != 65 || public_key[0] != 4u) {
        return false;
    }
    // Ignore first byte of public key
    const auto key_hash{ethash::keccak256(public_key.data() + 1, 64)};
    std::memcpy(out, &key_hash.bytes[12], 20);
    return true;
}

bool recover_address(uint8_t* out, const uint8_t message[32], const uint8_t signature[64], bool odd_y_parity,
                     secp256k1_context* context) noexcept {
    const auto recovered_public_key{recover(message, signature, odd_y_parity, context)};
    return public_key_to_address(out, recovered_public_key.value_or(Bytes{}));
}

}  // namespace silkworm::ecdsa
