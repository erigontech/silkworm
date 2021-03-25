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

#ifndef SILKWORM_CRYPTO_SNARK_HPP_
#define SILKWORM_CRYPTO_SNARK_HPP_

#include <optional>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>
#pragma GCC diagnostic pop

#include <silkworm/common/base.hpp>

// Utility functions for zkSNARK related precompiled contracts.
// See Yellow Paper, Appendix E "Precompiled Contracts", as well as
// https://eips.ethereum.org/EIPS/eip-196
// https://eips.ethereum.org/EIPS/eip-197

namespace silkworm::snark {

using Scalar = libff::bigint<libff::alt_bn128_q_limbs>;

// Must be called prior to invoking any other method.
// May be called many times from multiple threads.
void init_libff() noexcept;

Scalar to_scalar(ByteView big_endian) noexcept;

std::optional<libff::alt_bn128_G1> decode_g1_element(ByteView bytes64_be) noexcept;

std::optional<libff::alt_bn128_G2> decode_g2_element(ByteView bytes128_be) noexcept;

Bytes encode_g1_element(libff::alt_bn128_G1 p) noexcept;

}  // namespace silkworm::snark

#endif  // SILKWORM_CRYPTO_SNARK_HPP_
