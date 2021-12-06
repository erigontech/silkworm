/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_CHAIN_DIFFICULTY_HPP_
#define SILKWORM_CHAIN_DIFFICULTY_HPP_

#include <intx/intx.hpp>

#include <silkworm/chain/config.hpp>

namespace silkworm {

inline constexpr uint64_t kMinDifficulty{0x20000};

// Canonical difficulty of a Proof-of-Work block header.
// See Section 4.3.4 "Block Header Validity" of the Yellow Paper and also
// EIP-2, EIP-100, EIP-649, EIP-1234, EIP-2384, EIP-3554, EIP-4345.
intx::uint256 canonical_difficulty(uint64_t block_number, uint64_t block_timestamp,
                                   const intx::uint256& parent_difficulty, uint64_t parent_timestamp,
                                   bool parent_has_uncles, const ChainConfig& config);

}  // namespace silkworm

#endif  // SILKWORM_CHAIN_DIFFICULTY_HPP_
