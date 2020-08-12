/*
   Copyright 2020 The Silkworm Authors

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

namespace silkworm::snark {

static void init_libff() noexcept {
  [[maybe_unused]] static bool initialized = []() noexcept {
    libff::alt_bn128_pp::init_public_params();
    return true;
  }();
}

libff::bigint<libff::alt_bn128_q_limbs> to_bigint(ByteView be) noexcept {
  mpz_t m;
  mpz_init(m);
  mpz_import(m, be.size(), /*order=*/1, /*size=*/1, /*endian=*/0, /*nails=*/0, &be[0]);
  libff::bigint<libff::alt_bn128_q_limbs> out{m};
  mpz_clear(m);
  return out;
}

std::optional<libff::alt_bn128_G1> decode_g1_element(ByteView bytes64_be) noexcept {
  assert(bytes64_be.size() == 64);

  init_libff();
  using namespace libff;

  auto x{to_bigint(bytes64_be.substr(0, 32))};
  if (mpn_cmp(x.data, alt_bn128_modulus_q.data, alt_bn128_q_limbs) >= 0) {
    return {};
  }

  auto y{to_bigint(bytes64_be.substr(32, 32))};
  if (mpn_cmp(y.data, alt_bn128_modulus_q.data, alt_bn128_q_limbs) >= 0) {
    return {};
  }

  if (x.is_zero() && y.is_zero()) {
    return alt_bn128_G1::zero();
  }

  alt_bn128_G1 point{x, y, alt_bn128_Fq::one()};
  if (!point.is_well_formed()) {
    return {};
  }
  return point;
}

Bytes encode_g1_element(libff::alt_bn128_G1 p) noexcept {
  init_libff();

  Bytes out(64, '\0');
  if (p.is_zero()) {
    return out;
  }

  p.to_affine_coordinates();

  auto x{p.X.as_bigint()};
  auto y{p.Y.as_bigint()};

  std::memcpy(&out[0], y.data, 32);
  std::memcpy(&out[32], x.data, 32);

  std::reverse(out.begin(), out.end());
  return out;
}
}  // namespace silkworm::snark
