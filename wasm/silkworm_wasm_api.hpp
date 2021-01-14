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

#include <silkworm/chain/config.hpp>

#define SILKWORM_EXPORT __attribute__((visibility("default")))

extern "C" {

SILKWORM_EXPORT const silkworm::ChainConfig* silkworm_lookup_config(uint64_t chain_id);

SILKWORM_EXPORT silkworm::ChainConfig* silkworm_new_config(uint64_t chain_id);

SILKWORM_EXPORT void silkworm_config_set_update_block(silkworm::ChainConfig* config, evmc_revision update,
                                                      uint64_t block);

SILKWORM_EXPORT void silkworm_config_set_muir_glacier_block(silkworm::ChainConfig* config, uint64_t block);

SILKWORM_EXPORT uint64_t silkworm_difficulty(uint64_t block_number, uint64_t block_timestamp,
                                             uint64_t parent_difficulty, uint64_t parent_timestamp,
                                             bool parent_has_uncles, const silkworm::ChainConfig* config);
}

#endif  // SILKWORM_WASM_API_HPP_
