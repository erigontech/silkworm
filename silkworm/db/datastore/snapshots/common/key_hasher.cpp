// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "key_hasher.hpp"

#include <array>

#include "../common/encoding/murmur_hash3.hpp"

namespace silkworm::snapshots {

uint64_t KeyHasher::hash(ByteView key) const {
    std::array<uint64_t, 2> hash = {0, 0};
    encoding::Murmur3{salt_}.hash_x64_128(key.data(), key.size(), hash.data());
    return hash[0];
}

}  // namespace silkworm::snapshots
