// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <intx/intx.hpp>

#include <silkworm/core/types/transaction.hpp>

namespace silkworm {

// Words in EVM are 32-bytes long
constexpr uint64_t num_words(uint64_t num_bytes) noexcept {
    return num_bytes / 32 + static_cast<uint64_t>(num_bytes % 32 != 0);
}

namespace protocol {

    // Returns the intrinsic gas of a transaction.
    // Refer to g0 in Section 6.2 "Execution" of the Yellow Paper
    // and EIP-3860 "Limit and meter initcode".
    intx::uint128 intrinsic_gas(const UnsignedTransaction& txn, evmc_revision rev) noexcept;

    // Returns the floor cost (valid since Pectra)
    // Refer to: EIP-7623: Increase calldata cost
    uint64_t floor_cost(const UnsignedTransaction& txn) noexcept;

}  // namespace protocol

}  // namespace silkworm
