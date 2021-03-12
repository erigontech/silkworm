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

#ifndef SILKWORM_CRYPTO_ECDSA_HPP_
#define SILKWORM_CRYPTO_ECDSA_HPP_

// See Yellow Paper, Appendix F "Signing Transactions"

#include <optional>

#include <intx/intx.hpp>

#include <silkworm/common/base.hpp>

namespace silkworm::ecdsa {

constexpr auto kSecp256k1n{
    intx::from_string<intx::uint256>("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")};

constexpr auto kSecp256k1Halfn{kSecp256k1n >> 1};

struct YParityAndChainId {
    bool odd{false};
    std::optional<intx::uint256> chain_id{std::nullopt};  // EIP-155
};

// Calculates Y parity from signature's v.
// Unless v ∈ {27, 28}, chain_id will be returned as well.
// See https://eips.ethereum.org/EIPS/eip-155.
YParityAndChainId v_to_y_parity_and_chain_id(const intx::uint256& v);

// https://eips.ethereum.org/EIPS/eip-155
intx::uint256 y_parity_and_chain_id_to_v(bool odd, const std::optional<intx::uint256>& chain_id);

// Verifies whether the signature values are valid with
// the given chain rules.
bool is_valid_signature(const intx::uint256& r, const intx::uint256& s, bool homestead);

// Tries recover the public key used for message signing
std::optional<Bytes> recover(ByteView message, ByteView signature, bool odd_y_parity);

}  // namespace silkworm::ecdsa

#endif  // SILKWORM_CRYPTO_ECDSA_HPP_
