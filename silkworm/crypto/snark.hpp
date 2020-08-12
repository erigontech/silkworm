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

#ifndef SILKWORM_CRYPTO_SNARK_H_
#define SILKWORM_CRYPTO_SNARK_H_

#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <optional>
#include <silkworm/common/base.hpp>

// Utility functions for zkSNARK related precompiled contracts.
// See Yellow Paper, Appendix E "Precompiled Contracts", as well as
// https://eips.ethereum.org/EIPS/eip-196
// https://eips.ethereum.org/EIPS/eip-197

namespace silkworm::snark {

libff::bigint<libff::alt_bn128_q_limbs> to_bigint(ByteView big_endian) noexcept;

std::optional<libff::alt_bn128_G1> decode_g1_element(ByteView bytes64_be) noexcept;

Bytes encode_g1_element(libff::alt_bn128_G1 p) noexcept;

}  // namespace silkworm::snark

#endif  // SILKWORM_CRYPTO_SNARK_H_
