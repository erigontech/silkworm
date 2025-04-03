// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "y_parity_and_chain_id.hpp"

namespace silkworm {

intx::uint256 y_parity_and_chain_id_to_v(bool odd, const std::optional<intx::uint256>& chain_id) noexcept {
    if (chain_id.has_value()) {
        return chain_id.value() * 2 + 35 + odd;
    }
    return odd ? 28 : 27;
}

std::optional<YParityAndChainId> v_to_y_parity_and_chain_id(const intx::uint256& v) noexcept {
    YParityAndChainId res{};
    if (v == 27 || v == 28) {
        // pre EIP-155
        res.odd = v == 28;
        res.chain_id = std::nullopt;
    } else if (v < 35) {
        // EIP-155 implies v >= 35
        return std::nullopt;
    } else {
        // https://eips.ethereum.org/EIPS/eip-155
        // Find chain_id and y_parity ∈ {0, 1} such that
        // v = chain_id * 2 + 35 + y_parity
        intx::uint256 w{v - 35};
        res.odd = static_cast<uint64_t>(w) % 2;
        res.chain_id.emplace(w >> 1);  // w / 2
    }
    return res;
}

}  // namespace silkworm
