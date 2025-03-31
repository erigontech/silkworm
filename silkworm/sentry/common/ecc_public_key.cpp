// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ecc_public_key.hpp"

#include <stdexcept>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/secp256k1_context.hpp>

namespace silkworm::sentry {

Bytes EccPublicKey::serialized_std(bool is_compressed) const {
    auto& data = data_;
    secp256k1_pubkey public_key;
    memcpy(public_key.data, data.data(), sizeof(public_key.data));

    SecP256K1Context ctx;
    return ctx.serialize_public_key(&public_key, is_compressed);
}

Bytes EccPublicKey::serialized() const {
    Bytes data = serialized_std();
    std::copy(data.cbegin() + 1, data.cend(), data.begin());
    data.pop_back();
    return data;
}

std::string EccPublicKey::hex() const {
    return ::silkworm::to_hex(serialized());
}

EccPublicKey EccPublicKey::deserialize_std(ByteView serialized_data) {
    SecP256K1Context ctx;
    secp256k1_pubkey public_key;
    bool ok = ctx.parse_public_key(&public_key, serialized_data);
    if (!ok) {
        throw std::runtime_error("EccPublicKey::deserialize_std failed to parse a public key");
    }
    return EccPublicKey{Bytes{public_key.data, sizeof(public_key.data)}};
}

EccPublicKey EccPublicKey::deserialize(ByteView serialized_data) {
    Bytes data;
    data.reserve(serialized_data.size() + 1);
    data.push_back(SECP256K1_TAG_PUBKEY_UNCOMPRESSED);
    data += serialized_data;
    return deserialize_std(data);
}

EccPublicKey EccPublicKey::deserialize_hex(std::string_view hex) {
    auto data_opt = ::silkworm::from_hex(hex);
    if (!data_opt)
        throw std::runtime_error("EccPublicKey::deserialize_hex failed to parse a hex public key");
    return deserialize(data_opt.value());
}

bool operator<(const EccPublicKey& lhs, const EccPublicKey& rhs) {
    return lhs.data() < rhs.data();
}

}  // namespace silkworm::sentry
