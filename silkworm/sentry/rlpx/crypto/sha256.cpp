// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "sha256.hpp"

#include <evmone_precompiles/sha256.hpp>

namespace silkworm::sentry::rlpx::crypto {

Bytes sha256(ByteView data) {
    Bytes hash(32, 0);
    evmone::crypto::sha256(reinterpret_cast<std::byte*>(hash.data()),
                           reinterpret_cast<const std::byte*>(data.data()),
                           data.size());
    return hash;
}

}  // namespace silkworm::sentry::rlpx::crypto
