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
#include <secp256k1_recovery.h>

#include <silkworm/common/base.hpp>

namespace silkworm::ecdsa {

constexpr auto kSecp256k1n{
    intx::from_string<intx::uint256>("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")};

constexpr auto kSecp256k1Halfn{kSecp256k1n >> 1};

struct YParityAndChainId {
    bool odd{false};
    std::optional<intx::uint256> chain_id{std::nullopt};  // EIP-155
};

//! \brief Calculates Y parity from signature's V.
//! \param [in] v : signature V
//! \return Y parity and eventually chain Id
//! \remarks chain_id is always returned unless v ∈ {27, 28}
//! \see https://eips.ethereum.org/EIPS/eip-155.
std::optional<YParityAndChainId> v_to_y_parity_and_chain_id(const intx::uint256& v);

//! \see https://eips.ethereum.org/EIPS/eip-155
intx::uint256 y_parity_and_chain_id_to_v(bool odd, const std::optional<intx::uint256>& chain_id);

// Verifies whether the signature values are valid with
// the given chain rules.
//! Verifies whether the signature values are valid with the provided chain rules
//! \param [in] r : signature's r
//! \param [in] s : signature's s
//! \param [in] homestead : whether the chain has homestead rules
//! \return True or false
bool is_valid_signature(const intx::uint256& r, const intx::uint256& s, bool homestead);

//! \brief Creates a secp2561 context
//! \param [in] flags : creation flags
//! \return A raw pointer to context
//! \remarks Each thread should have its own context
secp256k1_context* create_context(int flags = SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

//! \brief Tries recover the public key used for message signing
//! \param [in] message : the signed message
//! \param [in] signature : the signature
//! \param [in] odd_y_parity : whether y parity is odd
//! \remarks An ecdsa recovery context is statically initialized
std::optional<evmc::address> recover_address(ByteView message, ByteView signature, bool odd_y_parity);

//! \brief Tries recover the public key used for message signing
//! \param [in] context : a pointer to ecdsa recovery context
//! \param [in] message : the signed message
//! \param [in] signature : the signature
//! \param [in] odd_y_parity : whether y parity is odd
std::optional<evmc::address> recover_address(secp256k1_context* context, ByteView message, ByteView signature, bool odd_y_parity);



}  // namespace silkworm::ecdsa

#endif  // SILKWORM_CRYPTO_ECDSA_HPP_
