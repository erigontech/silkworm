/*
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

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
    intx::uint128 floor_cost(const UnsignedTransaction& txn) noexcept;

}  // namespace protocol

}  // namespace silkworm
