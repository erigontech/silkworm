/*
   Copyright 2020-2022 The Silkworm Authors

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

#include <secp256k1_recovery.h>

#include <silkworm/common/base.hpp>

namespace silkworm::ecdsa {

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

//! \brief Tries recover the address used for message signing
//! \param [in] message : the signed message
//! \param [in] signature : the signature
//! \param [in] odd_y_parity : whether y parity is odd
//! \param [in] context : a pointer to an existing context. Should it be nullptr a default context is used
//! \return Whether the recovery has succeeded.
[[nodiscard]] bool recover_address(uint8_t* out, ByteView message, ByteView signature, bool odd_y_parity,
                                   secp256k1_context* context = nullptr) noexcept;

}  // namespace silkworm::ecdsa

#endif  // SILKWORM_CRYPTO_ECDSA_HPP_
