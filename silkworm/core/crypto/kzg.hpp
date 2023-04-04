/*
   Copyright 2023 The Silkworm Authors

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

#include <span>

#include <silkworm/core/types/hash.hpp>

// Cryptographic support for EIP-4844: Shard Blob Transactions.
// KZG stands for the commitment scheme introduced by Kate, Zaverucha, and Goldberg.
// See https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html

namespace silkworm {

// https://eips.ethereum.org/EIPS/eip-4844#helpers
Hash kzg_to_versioned_hash(ByteView kzg);

/**
 * Verify a KZG proof claiming that `p(z) == y`.
 *
 * @param[in]  commitment The KZG commitment corresponding to poly p(x)
 * @param[in]  z          The evaluation point
 * @param[in]  y          The claimed evaluation result
 * @param[in]  proof      The KZG proof
 * @return True if the proofs are valid, otherwise false
 *
 * @see https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#verify_kzg_proof
 */
bool verify_kzg_proof(
    std::span<const uint8_t, 48> commitment,
    std::span<const uint8_t, 32> z,
    std::span<const uint8_t, 32> y,
    std::span<const uint8_t, 48> proof);

}  // namespace silkworm
