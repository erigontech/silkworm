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

#ifndef SILKWORM_CRYPTO_ECDSA_H_
#define SILKWORM_CRYPTO_ECDSA_H_

// See Yellow Paper, Appendix F "Signing Transactions"

#include <intx/intx.hpp>
#include <optional>

#include "common/base.hpp"

namespace silkworm::ecdsa {

constexpr auto kSecp256k1n{intx::from_string<intx::uint256>(
    "115792089237316195423570985008687907852837564279074904382605163141518161494337")};

bool inputs_are_valid(const intx::uint256& v, const intx::uint256& r, const intx::uint256& s);

std::optional<Bytes> recover(ByteView message, ByteView signature, uint8_t recovery_id);
}  // namespace silkworm::ecdsa

#endif  // SILKWORM_CRYPTO_ECDSA_H_
