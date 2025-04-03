// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

// See Yellow Paper, Appendix F "Signing Transactions"
// and EIP-2: Homestead Hard-fork Changes.

#include <optional>

#include <intx/intx.hpp>

namespace silkworm {

// See Appendix F "Signing Transactions" of the Yellow Paper.
inline constexpr intx::uint256 kSecp256k1n{
    intx::from_string<intx::uint256>("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")};

inline constexpr intx::uint256 kSecp256k1Halfn{kSecp256k1n >> 1};

// Verifies whether the signature values are valid with
// the given chain rules.
//! Verifies whether the signature values are valid with the provided chain rules
//! \param [in] r : signature's r
//! \param [in] s : signature's s
//! \param [in] homestead : whether the chain has homestead rules
//! \return True or false
bool is_valid_signature(const intx::uint256& r, const intx::uint256& s, bool homestead) noexcept;

}  // namespace silkworm
