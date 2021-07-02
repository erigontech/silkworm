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

#include "silkworm_wasm_api.hpp"

#include <cstdlib>

#include <silkworm/chain/difficulty.hpp>
#include <silkworm/chain/intrinsic_gas.hpp>
#include <silkworm/common/util.hpp>

void* new_buffer(size_t size) { return std::malloc(size); }

void delete_buffer(void* ptr) { std::free(ptr); }

using namespace silkworm;

Bytes* new_bytes_from_hex(const char* data, size_t size) {
    std::optional<Bytes> res{from_hex(std::string_view{data, size})};
    if (!res) {
        return nullptr;
    }
    auto out{new Bytes};
    *out = *res;
    return out;
}

void delete_bytes(Bytes* x) { delete x; }

uint8_t* bytes_data(Bytes* str) { return str->data(); }

size_t bytes_length(const Bytes* str) { return str->length(); }

intx::uint256* new_uint256_le(uint64_t a, uint64_t b, uint64_t c, uint64_t d) { return new intx::uint256{a, b, c, d}; }

void delete_uint256(intx::uint256* x) { delete x; }

const ChainConfig* lookup_config(uint64_t chain_id) { return lookup_chain_config(chain_id); }

ChainConfig* new_config(uint64_t chain_id) {
    auto out{new ChainConfig};
    out->chain_id = chain_id;
    return out;
}

void delete_config(ChainConfig* x) { delete x; }

void config_set_fork_block(ChainConfig* config, evmc_revision fork, uint64_t block) {
    config->set_revision_block(fork, block);
}

void config_set_muir_glacier_block(ChainConfig* config, uint64_t block) { config->muir_glacier_block = block; }

void config_set_dao_block(ChainConfig* config, uint64_t block) { config->dao_block = block; }

void difficulty(intx::uint256* in_out, uint64_t block_number, uint64_t block_timestamp, uint64_t parent_timestamp,
                bool parent_has_uncles, const ChainConfig* config) {
    *in_out = canonical_difficulty(block_number, block_timestamp, /*parent_difficulty=*/*in_out, parent_timestamp,
                                   parent_has_uncles, *config);
}

Transaction* new_transaction(const Bytes* rlp) {
    ByteView view{*rlp};
    auto txn{new Transaction};
    if (rlp::decode(view, *txn) == rlp::DecodingResult::kOk && view.empty()) {
        return txn;
    } else {
        delete txn;
        return nullptr;
    }
}

void delete_transaction(Transaction* x) { delete x; }

bool check_intrinsic_gas(const Transaction* txn, bool homestead, bool istanbul) {
    intx::uint128 g0{intrinsic_gas(*txn, homestead, istanbul)};
    return txn->gas_limit >= g0;
}

const uint8_t* recover_sender(Transaction* txn) {
    txn->recover_sender();
    return txn->from ? txn->from->bytes : nullptr;
}

void keccak256(uint8_t* out, const Bytes* in) {
    ethash::hash256 hash{keccak256(*in)};
    std::memcpy(out, hash.bytes, kHashLength);
}

Account* new_account(uint64_t nonce, const intx::uint256* balance) {
    auto out{new Account};
    out->nonce = nonce;
    if (balance) {
        out->balance = *balance;
    }
    return out;
}

void delete_account(Account* x) { delete x; }

uint64_t account_nonce(const Account* a) { return a->nonce; }

intx::uint256* account_balance(Account* a) { return &(a->balance); }

uint8_t* account_code_hash(Account* a) { return a->code_hash.bytes; }

Block* new_block(const Bytes* rlp) {
    ByteView view{*rlp};
    auto block{new Block};
    if (rlp::decode(view, *block) == rlp::DecodingResult::kOk && view.empty()) {
        return block;
    } else {
        delete block;
        return nullptr;
    }
}

void delete_block(Block* x) { delete x; }

BlockHeader* block_header(Block* b) { return &(b->header); }

uint64_t header_number(const BlockHeader* header) { return header->number; }

uint8_t* header_state_root(BlockHeader* header) { return header->state_root.bytes; }

void block_recover_senders(Block* b) { b->recover_senders(); }

MemoryBuffer* new_state() { return new MemoryBuffer; }

void delete_state(MemoryBuffer* x) { delete x; }

uint8_t* state_root_hash_new(const MemoryBuffer* state) {
    evmc::bytes32 root_hash{state->state_root_hash()};
    void* out{new_buffer(kHashLength)};
    std::memcpy(out, root_hash.bytes, kHashLength);
    return static_cast<uint8_t*>(out);
}

static evmc::address address_from_ptr(const uint8_t* ptr) { return to_address({ptr, kAddressLength}); }

static evmc::bytes32 bytes32_from_ptr(const uint8_t* ptr) { return to_bytes32({ptr, kHashLength}); }

size_t state_number_of_accounts(const MemoryBuffer* state) { return state->number_of_accounts(); }

size_t state_storage_size(const MemoryBuffer* state, const uint8_t* address, const Account* account) {
    return state->storage_size(address_from_ptr(address), account->incarnation);
}

Account* state_read_account_new(const StateBuffer* state, const uint8_t* address) {
    std::optional<Account> account{state->read_account(address_from_ptr(address))};
    if (!account) {
        return nullptr;
    }

    auto out{new Account};
    *out = *account;
    return out;
}

Bytes* state_read_code_new(const StateBuffer* state, const uint8_t* code_hash) {
    auto out{new Bytes};
    *out = state->read_code(bytes32_from_ptr(code_hash));
    return out;
}

Bytes* state_read_storage_new(const StateBuffer* state, const uint8_t* address, const Account* account,
                              const Bytes* location) {
    evmc::bytes32 value{state->read_storage(address_from_ptr(address), account->incarnation, to_bytes32(*location))};
    auto out{new Bytes};
    *out = zeroless_view(value);
    return out;
}

void state_update_account(StateBuffer* state, const uint8_t* address, const Account* current_ptr) {
    std::optional<Account> current_opt;
    if (current_ptr) {
        current_opt = *current_ptr;
    }
    state->update_account(address_from_ptr(address), /* initial=*/std::nullopt, current_opt);
}

void state_update_code(StateBuffer* state, const uint8_t* address, const Account* account, const Bytes* code) {
    state->update_account_code(address_from_ptr(address), account->incarnation, account->code_hash, *code);
}

void state_update_storage(StateBuffer* state, const uint8_t* address, const Account* account, const Bytes* location,
                          const Bytes* value) {
    state->update_storage(address_from_ptr(address), account->incarnation, to_bytes32(*location), /*initial=*/{},
                          to_bytes32(*value));
}

Blockchain* new_blockchain(StateBuffer* state, const ChainConfig* config, const Block* genesis_block) {
    return new Blockchain{*state, *config, *genesis_block};
}

void delete_blockchain(Blockchain* x) { delete x; }

ValidationResult blockchain_insert_block(Blockchain* chain, Block* block, bool check_state_root) {
    return chain->insert_block(*block, check_state_root);
}

int main() { return 0; }
