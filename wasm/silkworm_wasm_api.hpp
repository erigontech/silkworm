/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_WASM_API_HPP_
#define SILKWORM_WASM_API_HPP_

#include <evmc/evmc.h>
#include <stdbool.h>
#include <stdint.h>

#include <intx/intx.hpp>
#include <silkworm/chain/config.hpp>
#include <silkworm/common/base.hpp>
#include <silkworm/types/transaction.hpp>

#define SILKWORM_EXPORT __attribute__((visibility("default")))

extern "C" {

SILKWORM_EXPORT void* silkworm_malloc(size_t size);
SILKWORM_EXPORT void silkworm_free(void* ptr);

SILKWORM_EXPORT silkworm::Bytes* silkworm_new_bytes_from_hex(const char* data, size_t size);
SILKWORM_EXPORT void silkworm_delete_bytes(silkworm::Bytes* x);

// a + b*2^64 + c*2^128 + d*2^192
SILKWORM_EXPORT intx::uint256* silkworm_new_uint256_le(uint64_t a, uint64_t b, uint64_t c, uint64_t d);
SILKWORM_EXPORT void silkworm_delete_uint256(intx::uint256* x);

SILKWORM_EXPORT const silkworm::ChainConfig* silkworm_lookup_config(uint64_t chain_id);

SILKWORM_EXPORT silkworm::ChainConfig* silkworm_new_config(uint64_t chain_id);
SILKWORM_EXPORT void silkworm_delete_config(silkworm::ChainConfig* x);

SILKWORM_EXPORT void silkworm_config_set_update_block(silkworm::ChainConfig* config, evmc_revision update,
                                                      uint64_t block);

SILKWORM_EXPORT void silkworm_config_set_muir_glacier_block(silkworm::ChainConfig* config, uint64_t block);

// in_out: in parent difficulty, out current difficulty
SILKWORM_EXPORT void silkworm_difficulty(intx::uint256* in_out, uint64_t block_number, uint64_t block_timestamp,
                                         uint64_t parent_timestamp, bool parent_has_uncles,
                                         const silkworm::ChainConfig* config);

SILKWORM_EXPORT silkworm::Transaction* silkworm_new_transaction(const silkworm::Bytes* rlp);
SILKWORM_EXPORT void silkworm_delete_transaction(silkworm::Transaction* x);

SILKWORM_EXPORT uint64_t silkworm_intrinsic_gas(const silkworm::Transaction* txn, bool homestead, bool istanbul);

// 0 chain_id means pre EIP-155
SILKWORM_EXPORT const uint8_t* silkworm_recover_sender(silkworm::Transaction* txn, bool homestead, uint64_t chain_id);
}

#endif  // SILKWORM_WASM_API_HPP_
