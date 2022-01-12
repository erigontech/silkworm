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

inline constexpr auto kSecp256k1n{
    intx::from_string<intx::uint256>("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")};

inline constexpr auto kSecp256k1Halfn{kSecp256k1n >> 1};

struct YParityAndChainId {
    bool odd{false};
    std::optional<intx::uint256> chain_id{std::nullopt};  // EIP-155
};

//! \brief Calculates Y parity from signature's V.
//! \param [in] v : signature V
//! \return Y parity and eventually chain Id
//! \remarks chain_id is always returned unless v ∈ {27, 28}
//! \see https://eips.ethereum.org/EIPS/eip-155.
std::optional<YParityAndChainId> v_to_y_parity_and_chain_id(const intx::uint256& v) noexcept;

//! \see https://eips.ethereum.org/EIPS/eip-155
intx::uint256 y_parity_and_chain_id_to_v(bool odd, const std::optional<intx::uint256>& chain_id) noexcept;

// Verifies whether the signature values are valid with
// the given chain rules.
//! Verifies whether the signature values are valid with the provided chain rules
//! \param [in] r : signature's r
//! \param [in] s : signature's s
//! \param [in] homestead : whether the chain has homestead rules
//! \return True or false
bool is_valid_signature(const intx::uint256& r, const intx::uint256& s, bool homestead) noexcept;

//! \brief Creates a secp2561 context
//! \param [in] flags : creation flags
//! \return A raw pointer to context
//! \remarks Each thread should have its own context
secp256k1_context* create_context(uint32_t flags = SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

//! \brief Tries recover public key used for message signing.
//! \param [in] message : the signed message
//! \param [in] signature : the signature
//! \param [in] odd_y_parity : whether y parity is odd
//! \param [in] context : a pointer to an existing context. Should it be nullptr a default context is used
//! \return An optional Bytes. Should it has no value the recovery has failed
//! This is different from recover_address as the whole 64 bytes are returned.
std::optional<Bytes> recover(ByteView message, ByteView signature, bool odd_y_parity,
                             secp256k1_context* context = nullptr) noexcept;

//! Tries extract address from recovered public key
//! \param [in] public_key :  The recovered public key
//! \return An optional evmc::address. Should it has no value the recovery has failed.
std::optional<evmc::address> public_key_to_address(const Bytes& public_key) noexcept;

//! \brief Tries recover the address used for message signing
//! \param [in] message : the signed message
//! \param [in] signature : the signature
//! \param [in] odd_y_parity : whether y parity is odd
//! \param [in] context : a pointer to an existing context. Should it be nullptr a default context is used
//! \return An optional address value. Should it has no value the recovery has failed
std::optional<evmc::address> recover_address(ByteView message, ByteView signature, bool odd_y_parity,
                                             secp256k1_context* context = nullptr) noexcept;

}  // namespace silkworm::ecdsa

#endif  // SILKWORM_CRYPTO_ECDSA_HPP_
