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

#include "blst12-381.hpp"

#include <algorithm>

namespace silkworm::blst {

template <std::size_t Extent>
static bool all_zeros(std::span<const uint8_t, Extent> span) {
    return std::ranges::all_of(span, [](uint8_t x) { return x == 0; });
}

std::optional<std::span<const uint8_t, 48>> decode_field_element(std::span<const uint8_t, 64> input) {
    if (!all_zeros(input.subspan<0, 16>())) {
        return std::nullopt;
    }
    return input.subspan<16, 48>();
}

std::optional<G1> decode_g1_point(std::span<const uint8_t, 128> input) {
    const std::optional<std::span<const uint8_t, 48>> x{decode_field_element(input.subspan<0, 64>())};
    if (!x) {
        return std::nullopt;
    }
    const std::optional<std::span<const uint8_t, 48>> y{decode_field_element(input.subspan<64, 64>())};
    if (!y) {
        return std::nullopt;
    }
    if (all_zeros(*x) && all_zeros(*y)) {
        // See "Point of infinity encoding" in
        // https://eips.ethereum.org/EIPS/eip-2537#fine-points-and-encoding-of-base-elements
        return G1{};
    }
    // blst_fp_from_bendian ???
    // TODO(yperbasis): implement
    return std::nullopt;
}

void g1_mul(G1* out, const G1* a, const Fr* b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    /* The last argument is the number of bits in the scalar */
    blst_p1_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}

void g2_mul(G2* out, const G2* a, const Fr* b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    /* The last argument is the number of bits in the scalar */
    blst_p2_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}

void g1_sub(G1* out, const G1* a, const G1* b) {
    G1 bneg = *b;
    blst_p1_cneg(&bneg, true);
    blst_p1_add_or_double(out, a, &bneg);
}

void g2_sub(G2* out, const G2* a, const G2* b) {
    G2 bneg = *b;
    blst_p2_cneg(&bneg, true);
    blst_p2_add_or_double(out, a, &bneg);
}

}  // namespace silkworm::blst
