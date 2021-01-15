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

SILKWORM_EXPORT void silkworm_delete(void* ptr) { std::free(ptr); }

intx::uint256* silkworm_new_uint256_le(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    // For some reason operator new causes import "wasi_snapshot_preview1"
    void* ptr{std::malloc(sizeof(intx::uint256))};
    auto out{static_cast<intx::uint256*>(ptr)};
    out->lo.lo = a;
    out->lo.hi = b;
    out->hi.lo = c;
    out->hi.hi = d;
    return out;
}

const silkworm::ChainConfig* silkworm_lookup_config(uint64_t chain_id) {
    return silkworm::lookup_chain_config(chain_id);
}

silkworm::ChainConfig* silkworm_new_config(uint64_t chain_id) {
    // For some reason operator new causes import "wasi_snapshot_preview1"
    void* ptr{std::malloc(sizeof(silkworm::ChainConfig))};
    auto out{static_cast<silkworm::ChainConfig*>(ptr)};
    *out = silkworm::ChainConfig{};
    out->chain_id = chain_id;
    return out;
}

void silkworm_config_set_update_block(silkworm::ChainConfig* config, evmc_revision update, uint64_t block) {
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

void silkworm_config_set_muir_glacier_block(silkworm::ChainConfig* config, uint64_t block) {
    config->muir_glacier_block = block;
}

void silkworm_difficulty(intx::uint256* in_out, uint64_t block_number, uint64_t block_timestamp,
                         uint64_t parent_timestamp, bool parent_has_uncles, const silkworm::ChainConfig* config) {
    *in_out = silkworm::canonical_difficulty(block_number, block_timestamp, /*parent_difficulty=*/*in_out,
                                             parent_timestamp, parent_has_uncles, *config);
}

int main() { return 0; }
