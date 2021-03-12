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

#include "snark.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/profiling.hpp>

#include <silkworm/common/endian.hpp>

namespace silkworm::snark {

void init_libff() noexcept {
    // magic static
    [[maybe_unused]] static bool initialized = []() noexcept {
        libff::inhibit_profiling_info = true;
        libff::inhibit_profiling_counters = true;
        libff::alt_bn128_pp::init_public_params();
        return true;
    }();
}

Scalar to_scalar(ByteView be) noexcept {
    mpz_t m;
    mpz_init(m);
    mpz_import(m, be.size(), /*order=*/1, /*size=*/1, /*endian=*/0, /*nails=*/0, &be[0]);
    Scalar out{m};
    mpz_clear(m);
    return out;
}

// Notation warning: Yellow Paper's p is the same libff's q.
// Returns x < p (YP notation).
static bool valid_element_of_fp(const Scalar& x) noexcept {
    return mpn_cmp(x.data, libff::alt_bn128_modulus_q.data, libff::alt_bn128_q_limbs) < 0;
}

std::optional<libff::alt_bn128_G1> decode_g1_element(ByteView bytes64_be) noexcept {
    assert(bytes64_be.size() == 64);

    Scalar x{to_scalar(bytes64_be.substr(0, 32))};
    if (!valid_element_of_fp(x)) {
        return {};
    }

    Scalar y{to_scalar(bytes64_be.substr(32, 32))};
    if (!valid_element_of_fp(y)) {
        return {};
    }

    if (x.is_zero() && y.is_zero()) {
        return libff::alt_bn128_G1::zero();
    }

    libff::alt_bn128_G1 point{x, y, libff::alt_bn128_Fq::one()};
    if (!point.is_well_formed()) {
        return {};
    }
    return point;
}

static std::optional<libff::alt_bn128_Fq2> decode_fp2_element(ByteView bytes64_be) noexcept {
    assert(bytes64_be.size() == 64);

    // big-endian encoding
    Scalar c0{to_scalar(bytes64_be.substr(32, 32))};
    Scalar c1{to_scalar(bytes64_be.substr(0, 32))};

    if (!valid_element_of_fp(c0) || !valid_element_of_fp(c1)) {
        return {};
    }

    return libff::alt_bn128_Fq2{c0, c1};
}

std::optional<libff::alt_bn128_G2> decode_g2_element(ByteView bytes128_be) noexcept {
    assert(bytes128_be.size() == 128);

    std::optional<libff::alt_bn128_Fq2> x{decode_fp2_element(bytes128_be.substr(0, 64))};
    if (!x) {
        return {};
    }

    std::optional<libff::alt_bn128_Fq2> y{decode_fp2_element(bytes128_be.substr(64, 64))};
    if (!y) {
        return {};
    }

    if (x->is_zero() && y->is_zero()) {
        return libff::alt_bn128_G2::zero();
    }

    libff::alt_bn128_G2 point{*x, *y, libff::alt_bn128_Fq2::one()};
    if (!point.is_well_formed()) {
        return {};
    }

    if (!(libff::alt_bn128_G2::order() * point).is_zero()) {
        // wrong order, doesn't belong to the subgroup G2
        return {};
    }

    return point;
}

Bytes encode_g1_element(libff::alt_bn128_G1 p) noexcept {
    Bytes out(64, '\0');
    if (p.is_zero()) {
        return out;
    }

    p.to_affine_coordinates();

    auto x{p.X.as_bigint()};
    auto y{p.Y.as_bigint()};

    // Here we convert little-endian data to big-endian output
    static_assert(SILKWORM_BYTE_ORDER == SILKWORM_LITTLE_ENDIAN);
    static_assert(sizeof(x.data) == 32);

    std::memcpy(&out[0], y.data, 32);
    std::memcpy(&out[32], x.data, 32);

    std::reverse(out.begin(), out.end());
    return out;
}

}  // namespace silkworm::snark
