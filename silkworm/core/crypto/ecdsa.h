// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

// See Yellow Paper, Appendix F "Signing Transactions"

#include <secp256k1.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

enum {
    SILKWORM_SECP256K1_CONTEXT_FLAGS = (SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
};

//! \brief Tries recover the address used for message signing
//! \param [in] message : the signed message
//! \param [in] signature : the signature
//! \param [in] recovery_id : the recovery id (0, 1, 2 or 3)
//! \param [in] context: a pointer to an existing secp256k1 context
//! \return Whether the recovery has succeeded
bool silkworm_recover_address(uint8_t out[20], const uint8_t message[32], const uint8_t signature[64],
                              uint8_t recovery_id, const secp256k1_context* context);

#if defined(__cplusplus)
}
#endif
