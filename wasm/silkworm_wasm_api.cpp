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
#include <silkworm/common/util.hpp>
#include <silkworm/execution/processor.hpp>

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

intx::uint256* new_uint256_le(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    auto out{new intx::uint256};
    out->lo.lo = a;
    out->lo.hi = b;
    out->hi.lo = c;
    out->hi.hi = d;
    return out;
}

void delete_uint256(intx::uint256* x) { delete x; }

const ChainConfig* lookup_config(uint64_t chain_id) { return lookup_chain_config(chain_id); }

ChainConfig* new_config(uint64_t chain_id) {
    auto out{new ChainConfig};
    out->chain_id = chain_id;
    return out;
}

void delete_config(ChainConfig* x) { delete x; }

void config_set_update_block(ChainConfig* config, evmc_revision update, uint64_t block) {
    switch (update) {
        case EVMC_FRONTIER:
            // frontier block is always 0
            return;
        case EVMC_HOMESTEAD:
            config->homestead_block = block;
            return;
        case EVMC_TANGERINE_WHISTLE:
            config->tangerine_whistle_block = block;
            return;
        case EVMC_SPURIOUS_DRAGON:
            config->spurious_dragon_block = block;
            return;
        case EVMC_BYZANTIUM:
            config->byzantium_block = block;
            return;
        case EVMC_CONSTANTINOPLE:
            config->constantinople_block = block;
            return;
        case EVMC_PETERSBURG:
            config->petersburg_block = block;
            return;
        case EVMC_ISTANBUL:
            config->istanbul_block = block;
            return;
        case EVMC_BERLIN:
            config->berlin_block = block;
            return;
    }
}

void config_set_muir_glacier_block(ChainConfig* config, uint64_t block) { config->muir_glacier_block = block; }

void difficulty(intx::uint256* in_out, uint64_t block_number, uint64_t block_timestamp, uint64_t parent_timestamp,
                bool parent_has_uncles, const ChainConfig* config) {
    *in_out = canonical_difficulty(block_number, block_timestamp, /*parent_difficulty=*/*in_out, parent_timestamp,
                                   parent_has_uncles, *config);
}

Transaction* new_transaction(const Bytes* rlp) {
    ByteView view{*rlp};
    auto txn{new Transaction};
    if (rlp::decode(view, *txn) == rlp::DecodingError::kOk && view.empty()) {
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

const uint8_t* recover_sender(Transaction* txn, bool homestead, uint64_t chain_id) {
    if (chain_id == 0) {
        txn->recover_sender(homestead, std::nullopt);
    } else {
        txn->recover_sender(homestead, chain_id);
    }
    return txn->from ? txn->from->bytes : nullptr;
}

int main() { return 0; }
