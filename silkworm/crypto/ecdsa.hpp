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
#include <silkworm/common/base.hpp>

namespace silkworm::ecdsa {

constexpr auto kSecp256k1n{
    intx::from_string<intx::uint256>("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")};
constexpr auto kSecp256k1Halfn{kSecp256k1n >> 1};

struct RecoveryId {
    uint8_t recovery_id{0};
    std::optional<intx::uint256> eip155_chain_id{};
};

// Calculates the recovery ID from signature's v.
// Returned recovery_id is always 0 or 1.
// Unless v ∈ {27, 28}, eip155_chain_id will be returned as well.
// See https://eips.ethereum.org/EIPS/eip-155.
RecoveryId get_signature_recovery_id(const intx::uint256& v);

// Verifies whether the signature values are valid with
// the given chain rules.
bool is_valid_signature(const intx::uint256& r, const intx::uint256& s, bool homestead);

// Tries recover the public key used for message signing
std::optional<Bytes> recover(ByteView message, ByteView signature, uint8_t recovery_id);

}  // namespace silkworm::ecdsa

#endif  // SILKWORM_CRYPTO_ECDSA_H_
