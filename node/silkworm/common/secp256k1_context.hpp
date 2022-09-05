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

#pragma once

#include <secp256k1.h>

#include <utility>

#include <gsl/pointers>
#include <secp256k1_recovery.h>
#include <silkpre/ecdsa.h>

#include <silkworm/common/base.hpp>

namespace silkworm {

class SecP256K1Context final {
  public:
    explicit SecP256K1Context(bool allow_verify = true, bool allow_sign = false)
        : context_(secp256k1_context_create(SecP256K1Context::flags(allow_verify, allow_sign))) {}

    ~SecP256K1Context() {
        secp256k1_context_destroy(context_);
    }

    SecP256K1Context(const SecP256K1Context&) = delete;
    SecP256K1Context& operator=(const SecP256K1Context&) = delete;

    // escape hatch
    secp256k1_context* raw() { return context_; }

    [[nodiscard]] bool verify_private_key_data(const ByteView& data) const {
        return secp256k1_ec_seckey_verify(context_, data.data());
    }

    bool create_public_key(secp256k1_pubkey* public_key, const ByteView& private_key) const {
        return secp256k1_ec_pubkey_create(context_, public_key, private_key.data());
    }

    Bytes serialize_public_key(const secp256k1_pubkey* public_key, bool is_compressed) const;

    bool parse_public_key(secp256k1_pubkey* public_key, const ByteView& public_key_data) const {
        return secp256k1_ec_pubkey_parse(context_, public_key, public_key_data.data(), public_key_data.size());
    }

    bool compute_ecdh_secret(
        Bytes& shared_secret,
        const secp256k1_pubkey* public_key,
        const ByteView& private_key) const {
        return silkpre_secp256k1_ecdh(context_, shared_secret.data(), public_key, private_key.data());
    }

    bool sign_recoverable(secp256k1_ecdsa_recoverable_signature* signature, ByteView data, ByteView private_key) {
        if (data.size() != 32)
            return false;
        return secp256k1_ecdsa_sign_recoverable(context_, signature, data.data(), private_key.data(), nullptr, nullptr);
    }

    bool recover_signature_public_key(
        secp256k1_pubkey* public_key,
        const secp256k1_ecdsa_recoverable_signature* signature,
        ByteView data) {
        if (data.size() != 32)
            return false;
        return secp256k1_ecdsa_recover(context_, public_key, signature, data.data());
    }

    std::pair<Bytes, uint8_t> serialize_recoverable_signature(const secp256k1_ecdsa_recoverable_signature* signature) {
        Bytes data(64, 0);
        int recovery_id;
        secp256k1_ecdsa_recoverable_signature_serialize_compact(context_, data.data(), &recovery_id, signature);
        return {data, static_cast<uint8_t>(recovery_id)};
    }

    bool parse_recoverable_signature(
        secp256k1_ecdsa_recoverable_signature* signature,
        const ByteView& signature_data,
        uint8_t recovery_id) {
        if (signature_data.size() != 64)
            return false;
        return secp256k1_ecdsa_recoverable_signature_parse_compact(
            context_,
            signature,
            signature_data.data(),
            static_cast<int>(recovery_id));
    }

    static const size_t kPublicKeySizeCompressed;
    static const size_t kPublicKeySizeUncompressed;

  private:
    static unsigned int flags(bool allow_verify, bool allow_sign);

    gsl::owner<secp256k1_context*> context_;
};

}  // namespace silkworm
