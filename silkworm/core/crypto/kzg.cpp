/*
 * Copyright 2021 Benjamin Edgington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "kzg.hpp"

#include <blst.h>

#include <evmone_precompiles/sha256.hpp>

#include <silkworm/core/protocol/param.hpp>

// Based on https://github.com/ethereum/c-kzg-4844/blob/main/src/c_kzg_4844.c
// and modified for Silkworm.

namespace silkworm {

///////////////////////////////////////////////////////////////////////////////
// Types
///////////////////////////////////////////////////////////////////////////////

using G1 = blst_p1;
using G2 = blst_p2;
using Fr = blst_fr;

///////////////////////////////////////////////////////////////////////////////
// Constants
///////////////////////////////////////////////////////////////////////////////

// KZG_SETUP_G2[1] printed by cmd/dev/kzg_g2_uncompress
// See https://github.com/ethereum/consensus-specs/blob/dev/presets/mainnet/trusted_setups/trusted_setup_4096.json
static const G2 kKzgSetupG2_1{
    {{{0x6120a2099b0379f9, 0xa2df815cb8210e4e, 0xcb57be5577bd3d4f,
       0x62da0ea89a0c93f8, 0x02e0ee16968e150d, 0x171f09aea833acd5},
      {0x11a3670749dfd455, 0x04991d7b3abffadc, 0x85446a8e14437f41,
       0x27174e7b4e76e3f2, 0x7bfa6dd397f60a20, 0x02fcc329ac07080f}}},
    {{{0xaa130838793b2317, 0xe236dd220f891637, 0x6502782925760980,
       0xd05c25f60557ec89, 0x6095767a44064474, 0x185693917080d405},
      {0x549f9e175b03dc0a, 0x32c0c95a77106cfe, 0x64a74eae5705d080,
       0x53deeaf56659ed9e, 0x09a1d368508afb93, 0x12cf3a4525b5e9bd}}},
    {{{0x760900000002fffd, 0xebf4000bc40c0002, 0x5f48985753c758ba,
       0x77ce585370525745, 0x5c071a97a256ec6d, 0x15f65ec3fa80e493},
      {0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
       0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}}};

///////////////////////////////////////////////////////////////////////////////
// Helper Functions
///////////////////////////////////////////////////////////////////////////////

Hash kzg_to_versioned_hash(ByteView kzg) {
    Hash hash;
    evmone::crypto::sha256(reinterpret_cast<std::byte*>(hash.bytes),
                           reinterpret_cast<const std::byte*>(kzg.data()), kzg.length());
    hash.bytes[0] = protocol::kBlobCommitmentVersionKzg;
    return hash;
}

/**
 * Multiply a G1 group element by a field element.
 *
 * @param[out] out @p a * @p b
 * @param[in]  a   The G1 group element
 * @param[in]  b   The multiplier
 */
static void g1_mul(G1* out, const G1* a, const Fr* b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    /* The last argument is the number of bits in the scalar */
    blst_p1_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}

/**
 * Multiply a G2 group element by a field element.
 *
 * @param[out] out @p a * @p b
 * @param[in]  a   The G2 group element
 * @param[in]  b   The multiplier
 */
static void g2_mul(G2* out, const G2* a, const Fr* b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    /* The last argument is the number of bits in the scalar */
    blst_p2_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}

/**
 * Subtraction of G1 group elements.
 *
 * @param[out] out @p a - @p b
 * @param[in]  a   A G1 group element
 * @param[in]  b   The G1 group element to be subtracted
 */
static void g1_sub(G1* out, const G1* a, const G1* b) {
    G1 bneg = *b;
    blst_p1_cneg(&bneg, true);
    blst_p1_add_or_double(out, a, &bneg);
}

/**
 * Subtraction of G2 group elements.
 *
 * @param[out] out @p a - @p b
 * @param[in]  a   A G2 group element
 * @param[in]  b   The G2 group element to be subtracted
 */
static void g2_sub(G2* out, const G2* a, const G2* b) {
    G2 bneg = *b;
    blst_p2_cneg(&bneg, true);
    blst_p2_add_or_double(out, a, &bneg);
}

/**
 * Perform pairings and test whether the outcomes are equal in G_T.
 *
 * Tests whether `e(a1, a2) == e(b1, b2)`.
 *
 * @param[in] a1 A G1 group point for the first pairing
 * @param[in] a2 A G2 group point for the first pairing
 * @param[in] b1 A G1 group point for the second pairing
 * @param[in] b2 A G2 group point for the second pairing
 *
 * @retval true  The pairings were equal
 * @retval false The pairings were not equal
 */
static bool pairings_verify(
    const G1* a1, const G2* a2, const G1* b1, const G2* b2) {
    blst_fp12 loop0, loop1, gt_point;
    blst_p1_affine aa1, bb1;
    blst_p2_affine aa2, bb2;

    /*
     * As an optimisation, we want to invert one of the pairings,
     * so we negate one of the points.
     */
    G1 a1neg = *a1;
    blst_p1_cneg(&a1neg, true);

    blst_p1_to_affine(&aa1, &a1neg);
    blst_p1_to_affine(&bb1, b1);
    blst_p2_to_affine(&aa2, a2);
    blst_p2_to_affine(&bb2, b2);

    blst_miller_loop(&loop0, &aa2, &aa1);
    blst_miller_loop(&loop1, &bb2, &bb1);

    blst_fp12_mul(&gt_point, &loop0, &loop1);
    blst_final_exp(&gt_point, &gt_point);

    return blst_fp12_is_one(&gt_point);
}

///////////////////////////////////////////////////////////////////////////////
// BLS12-381 Helper Functions
///////////////////////////////////////////////////////////////////////////////

/**
 * Convert untrusted bytes to a trusted and validated BLS scalar field
 * element.
 *
 * @param[out] out The field element to store the deserialized data
 * @param[in]  b   A 32-byte array containing the serialized field element
 */
static bool bytes_to_bls_field(Fr* out, std::span<const uint8_t, 32> b) {
    blst_scalar tmp;
    blst_scalar_from_bendian(&tmp, b.data());
    if (!blst_scalar_fr_check(&tmp)) {
        return false;
    }
    blst_fr_from_scalar(out, &tmp);
    return true;
}

/**
 * Perform BLS validation required by the types KZGProof and KZGCommitment.
 *
 * @remark This function deviates from the spec because it returns (via an
 *     output argument) the g1 point. This way is more efficient (faster)
 *     but the function name is a bit misleading.
 *
 * @param[out]  out The output g1 point
 * @param[in]   b   The proof/commitment bytes
 */
static bool validate_kzg_g1(G1* out, std::span<const uint8_t, 48> b) {
    blst_p1_affine p1_affine;

    /* Convert the bytes to a p1 point */
    /* The uncompress routine checks that the point is on the curve */
    if (blst_p1_uncompress(&p1_affine, b.data()) != BLST_SUCCESS) {
        return false;
    }
    blst_p1_from_affine(out, &p1_affine);

    /* The point at infinity is accepted! */
    if (blst_p1_is_inf(out)) {
        return true;
    }

    /* The point must be on the right subgroup */
    return blst_p1_in_g1(out);
}

///////////////////////////////////////////////////////////////////////////////
// KZG Functions
///////////////////////////////////////////////////////////////////////////////

/**
 * Helper function: Verify KZG proof claiming that `p(z) == y`.
 *
 * Given a @p commitment to a polynomial, a @p proof for @p z, and the
 * claimed value @p y at @p z, verify the claim.
 *
 * @param[in]  commitment The commitment to a polynomial
 * @param[in]  z          The point at which the proof is to be checked
 *                        (opened)
 * @param[in]  y          The claimed value of the polynomial at @p z
 * @param[in]  proof      A proof of the value of the polynomial at the
 *                        point @p z
 * @return `true` if the proof is valid, `false` if not
 */
static bool verify_kzg_proof_impl(
    const G1* commitment,
    const Fr* z,
    const Fr* y,
    const G1* proof) {
    G2 x_g2, X_minus_z;
    G1 y_g1, P_minus_y;

    /* Calculate: X_minus_z */
    g2_mul(&x_g2, blst_p2_generator(), z);
    g2_sub(&X_minus_z, &kKzgSetupG2_1, &x_g2);

    /* Calculate: P_minus_y */
    g1_mul(&y_g1, blst_p1_generator(), y);
    g1_sub(&P_minus_y, commitment, &y_g1);

    /* Verify: P - y = Q * (X - z) */
    return pairings_verify(&P_minus_y, blst_p2_generator(), proof, &X_minus_z);
}

bool verify_kzg_proof(
    std::span<const uint8_t, 48> commitment,
    std::span<const uint8_t, 32> z,
    std::span<const uint8_t, 32> y,
    std::span<const uint8_t, 48> proof) {
    Fr z_fr, y_fr;
    G1 commitment_g1, proof_g1;

    if (!validate_kzg_g1(&commitment_g1, commitment)) {
        return false;
    }
    if (!bytes_to_bls_field(&z_fr, z)) {
        return false;
    }
    if (!bytes_to_bls_field(&y_fr, y)) {
        return false;
    }
    if (!validate_kzg_g1(&proof_g1, proof)) {
        return false;
    }

    return verify_kzg_proof_impl(
        &commitment_g1, &z_fr, &y_fr, &proof_g1);
}

}  // namespace silkworm
