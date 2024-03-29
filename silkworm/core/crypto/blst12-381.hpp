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

// BLS12-381 curve cryptography
namespace silkworm::blst {

using G1 = blst_p1;
using G2 = blst_p2;
using Fr = blst_fr;

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
