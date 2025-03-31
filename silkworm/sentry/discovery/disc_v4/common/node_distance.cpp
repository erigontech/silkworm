// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "node_distance.hpp"

#include <bit>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/sentry/common/crypto/xor.hpp>

namespace silkworm::sentry::discovery::disc_v4 {

size_t node_distance(const EccPublicKey& id1, const EccPublicKey& id2) {
    auto id1_hash = keccak256(id1.serialized());
    auto id2_hash = keccak256(id2.serialized());

    Bytes diff{ByteView{id1_hash.bytes}};
    ByteView id2_hash_bytes{id2_hash.bytes};

    crypto::xor_bytes(diff, id2_hash_bytes);

    size_t same_bits_count = 0;
    for (uint8_t byte : diff) {
        int same_bits = std::countl_zero(byte);
        same_bits_count += static_cast<size_t>(same_bits);
        if (same_bits < 8) {
            break;
        }
    }
    return diff.size() * 8 - same_bits_count;
}

}  // namespace silkworm::sentry::discovery::disc_v4
