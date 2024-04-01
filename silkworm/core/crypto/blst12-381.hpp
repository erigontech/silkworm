/*
   Copyright 2024 The Silkworm Authors

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

#include <blst.h>

#include <cstdint>
#include <optional>
#include <span>

// BLS12-381 curve cryptography
namespace silkworm::blst {

using G1 = blst_p1;
using G2 = blst_p2;
using Fr = blst_fr;

// From https://eips.ethereum.org/EIPS/eip-2537#fine-points-and-encoding-of-base-elements:
// A base field element (Fp) is encoded as 64 bytes by performing the BigEndian encoding of the corresponding (unsigned)
// integer. Due to the size of p, the top 16 bytes are always zeroes. 64 bytes are chosen to have 32 byte aligned ABI
// (representable as e.g. bytes32[2] or uint256[2] with the latter assuming the BigEndian encoding). The corresponding
// integer must be less than field modulus.
std::optional<std::span<const uint8_t, 48>> decode_field_element(std::span<const uint8_t, 64>);

// From https://eips.ethereum.org/EIPS/eip-2537#fine-points-and-encoding-of-base-elements:
// Points of G1 and G2 are encoded as byte concatenation of the respective encodings of the x and y coordinates.
// Total encoding length for a G1 point is thus 128 bytes and for a G2 point is 256 bytes.
std::optional<G1> decode_g1_point(std::span<const uint8_t, 128>);

/**
 * Multiply a G1 group element by a field element.
 *
 * @param[out] out @p a * @p b
 * @param[in]  a   The G1 group element
 * @param[in]  b   The multiplier
 */
void g1_mul(G1* out, const G1* a, const Fr* b);

/**
 * Multiply a G2 group element by a field element.
 *
 * @param[out] out @p a * @p b
 * @param[in]  a   The G2 group element
 * @param[in]  b   The multiplier
 */
void g2_mul(G2* out, const G2* a, const Fr* b);

/**
 * Subtraction of G1 group elements.
 *
 * @param[out] out @p a - @p b
 * @param[in]  a   A G1 group element
 * @param[in]  b   The G1 group element to be subtracted
 */
void g1_sub(G1* out, const G1* a, const G1* b);

/**
 * Subtraction of G2 group elements.
 *
 * @param[out] out @p a - @p b
 * @param[in]  a   A G2 group element
 * @param[in]  b   The G2 group element to be subtracted
 */
void g2_sub(G2* out, const G2* a, const G2* b);

}  // namespace silkworm::blst
