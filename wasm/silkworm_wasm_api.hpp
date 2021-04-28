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

// Preliminary Silkworm API for WebAssembly.
// Currently it's unstable and is likely to change.
// Used for https://torquem.ch/eth_tests.html

#include <stdbool.h>
#include <stdint.h>

#include <evmc/evmc.h>
#include <intx/intx.hpp>

#include <silkworm/chain/blockchain.hpp>
#include <silkworm/common/base.hpp>
#include <silkworm/state/memory_buffer.hpp>
#include <silkworm/types/account.hpp>
#include <silkworm/types/transaction.hpp>

#define SILKWORM_EXPORT __attribute__((visibility("default")))

extern "C" {

SILKWORM_EXPORT void* new_buffer(size_t size);
SILKWORM_EXPORT void delete_buffer(void* ptr);

SILKWORM_EXPORT silkworm::Bytes* new_bytes_from_hex(const char* data, size_t size);
SILKWORM_EXPORT void delete_bytes(silkworm::Bytes* x);

SILKWORM_EXPORT uint8_t* bytes_data(silkworm::Bytes* str);

SILKWORM_EXPORT size_t bytes_length(const silkworm::Bytes* str);

// a + b*2^64 + c*2^128 + d*2^192
SILKWORM_EXPORT intx::uint256* new_uint256_le(uint64_t a, uint64_t b, uint64_t c, uint64_t d);
SILKWORM_EXPORT void delete_uint256(intx::uint256* x);

SILKWORM_EXPORT const silkworm::ChainConfig* lookup_config(uint64_t chain_id);

SILKWORM_EXPORT silkworm::ChainConfig* new_config(uint64_t chain_id);
SILKWORM_EXPORT void delete_config(silkworm::ChainConfig* x);

SILKWORM_EXPORT void config_set_fork_block(silkworm::ChainConfig* config, evmc_revision fork, uint64_t block);

SILKWORM_EXPORT void config_set_muir_glacier_block(silkworm::ChainConfig* config, uint64_t block);

SILKWORM_EXPORT void config_set_dao_block(silkworm::ChainConfig* config, uint64_t block);

// in_out: in parent difficulty, out current difficulty
SILKWORM_EXPORT void difficulty(intx::uint256* in_out, uint64_t block_number, uint64_t block_timestamp,
                                uint64_t parent_timestamp, bool parent_has_uncles, const silkworm::ChainConfig* config);

SILKWORM_EXPORT silkworm::Transaction* new_transaction(const silkworm::Bytes* rlp);
SILKWORM_EXPORT void delete_transaction(silkworm::Transaction* x);

SILKWORM_EXPORT bool check_intrinsic_gas(const silkworm::Transaction* txn, bool homestead, bool istanbul);

SILKWORM_EXPORT const uint8_t* recover_sender(silkworm::Transaction* txn);

SILKWORM_EXPORT void keccak256(uint8_t* out, const silkworm::Bytes* in);

SILKWORM_EXPORT silkworm::Account* new_account(uint64_t nonce, const intx::uint256* balance);
SILKWORM_EXPORT void delete_account(silkworm::Account* x);

SILKWORM_EXPORT uint64_t account_nonce(const silkworm::Account* a);

SILKWORM_EXPORT intx::uint256* account_balance(silkworm::Account* a);

SILKWORM_EXPORT uint8_t* account_code_hash(silkworm::Account* a);

SILKWORM_EXPORT silkworm::Block* new_block(const silkworm::Bytes* rlp);
SILKWORM_EXPORT void delete_block(silkworm::Block* x);

SILKWORM_EXPORT silkworm::BlockHeader* block_header(silkworm::Block* b);

SILKWORM_EXPORT uint64_t header_number(const silkworm::BlockHeader* header);

SILKWORM_EXPORT uint8_t* header_state_root(silkworm::BlockHeader* header);

SILKWORM_EXPORT void block_recover_senders(silkworm::Block* b);

SILKWORM_EXPORT silkworm::MemoryBuffer* new_state();
SILKWORM_EXPORT void delete_state(silkworm::MemoryBuffer* x);

SILKWORM_EXPORT size_t state_number_of_accounts(const silkworm::MemoryBuffer* state);

SILKWORM_EXPORT size_t state_storage_size(const silkworm::MemoryBuffer* state, const uint8_t* address,
                                          const silkworm::Account* account);

// Result has to be freed with delete_buffer
SILKWORM_EXPORT uint8_t* state_root_hash_new(const silkworm::MemoryBuffer* state);

// Result has to be freed with delete_account
SILKWORM_EXPORT silkworm::Account* state_read_account_new(const silkworm::StateBuffer* state, const uint8_t* address);

// Result has to be freed with delete_bytes
SILKWORM_EXPORT silkworm::Bytes* state_read_code_new(const silkworm::StateBuffer* state, const uint8_t* code_hash);

// Result has to be freed with delete_bytes
SILKWORM_EXPORT silkworm::Bytes* state_read_storage_new(const silkworm::StateBuffer* state, const uint8_t* address,
                                                        const silkworm::Account* account,
                                                        const silkworm::Bytes* location);

SILKWORM_EXPORT void state_update_account(silkworm::StateBuffer* state, const uint8_t* address,
                                          const silkworm::Account* current);

SILKWORM_EXPORT void state_update_code(silkworm::StateBuffer* state, const uint8_t* address,
                                       const silkworm::Account* account, const silkworm::Bytes* code);

SILKWORM_EXPORT void state_update_storage(silkworm::StateBuffer* state, const uint8_t* address,
                                          const silkworm::Account* account, const silkworm::Bytes* location,
                                          const silkworm::Bytes* value);

SILKWORM_EXPORT silkworm::Blockchain* new_blockchain(silkworm::StateBuffer* state, const silkworm::ChainConfig* config,
                                                     const silkworm::Block* genesis_block);
SILKWORM_EXPORT void delete_blockchain(silkworm::Blockchain* x);

SILKWORM_EXPORT silkworm::ValidationResult blockchain_insert_block(silkworm::Blockchain* chain, silkworm::Block* block,
                                                                   bool check_state_root);
}

#endif  // SILKWORM_WASM_API_HPP_
