// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <intx/intx.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

// Default incarnation for smart contracts is 1;
// contracts that were previously destructed and then re-created will have an incarnation greater than 1.
// The incarnation of non-contracts (externally owned accounts) is always 0.
inline constexpr uint64_t kDefaultIncarnation{1};

struct Account {
    uint64_t nonce{0};
    intx::uint256 balance;
    evmc::bytes32 code_hash{kEmptyHash};
    uint64_t incarnation{0};
    uint64_t previous_incarnation{0};

    //! \brief Serialize the account into its Recursive-Length Prefix (RLP) representation
    Bytes rlp(const evmc::bytes32& storage_root) const;

    friend bool operator==(const Account&, const Account&) = default;

    std::string to_string() const;
};

}  // namespace silkworm
