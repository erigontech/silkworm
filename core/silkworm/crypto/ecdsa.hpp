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

#include <stddef.h>
#include <stdint.h>

#include <secp256k1_recovery.h>

namespace silkworm::ecdsa {

//! \brief Creates a secp2561 context
//! \param [in] flags : creation flags
//! \return A raw pointer to context
//! \remarks Each thread should have its own context
secp256k1_context* create_context(uint32_t flags = SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

//! \brief Tries recover the address used for message signing
//! \param [in] message : the signed message
//! \param [in] signature : the signature
//! \param [in] odd_y_parity : whether y parity is odd
//! \param [in] context: a pointer to an existing context. Should it be nullptr a default context is used
//! \return Whether the recovery has succeeded.
[[nodiscard]] bool recover_address(uint8_t* out, const uint8_t message[32], const uint8_t signature[64],
                                   bool odd_y_parity, secp256k1_context* context = nullptr) noexcept;

}  // namespace silkworm::ecdsa

#endif  // SILKWORM_CRYPTO_ECDSA_HPP_
