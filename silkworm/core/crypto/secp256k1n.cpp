// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "secp256k1n.hpp"

namespace silkworm {

bool is_valid_signature(const intx::uint256& r, const intx::uint256& s, bool homestead) noexcept {
    if (!r || !s) {
        return false;
    }
    if (r >= kSecp256k1n || s >= kSecp256k1n) {
        return false;
    }
    // https://eips.ethereum.org/EIPS/eip-2
    if (homestead && s > kSecp256k1Halfn) {
        return false;
    }
    return true;
}

}  // namespace silkworm
