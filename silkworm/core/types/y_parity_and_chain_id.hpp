// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

// See Yellow Paper, Appendix F "Signing Transactions"
// and EIP-155: Simple replay attack protection.

#include <optional>

#include <intx/intx.hpp>

namespace silkworm {

struct YParityAndChainId {
    bool odd{false};
    std::optional<intx::uint256> chain_id{std::nullopt};  // EIP-155
};

//! \brief Calculates Y parity from signature's V.
//! \param [in] v : signature V
//! \return Y parity and eventually chain Id
//! \remarks chain_id is always returned unless v ∈ {27, 28}
//! \see https://eips.ethereum.org/EIPS/eip-155.
std::optional<YParityAndChainId> v_to_y_parity_and_chain_id(const intx::uint256& v) noexcept;

//! \see https://eips.ethereum.org/EIPS/eip-155
intx::uint256 y_parity_and_chain_id_to_v(bool odd, const std::optional<intx::uint256>& chain_id) noexcept;

}  // namespace silkworm
