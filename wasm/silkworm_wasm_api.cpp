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

#include <silkworm/chain/difficulty.hpp>

const silkworm::ChainConfig* silkworm_lookup_config(uint64_t chain_id) {
    return silkworm::lookup_chain_config(chain_id);
}

silkworm::ChainConfig* silkworm_new_config(uint64_t chain_id) {
    // TODO(Andrew) operator new
    void* ptr{malloc(sizeof(silkworm::ChainConfig))};
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

uint64_t silkworm_difficulty(uint64_t block_number, uint64_t block_timestamp, uint64_t parent_difficulty,
                             uint64_t parent_timestamp, bool parent_has_uncles, const silkworm::ChainConfig* config) {
    intx::uint256 x{silkworm::canonical_difficulty(block_number, block_timestamp, parent_difficulty, parent_timestamp,
                                                   parent_has_uncles, *config)};
    return static_cast<uint64_t>(x);
}

int main() { return 0; }
