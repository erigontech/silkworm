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

#include "config.hpp"

namespace silkworm {

bool operator==(const ChainConfig& a, const ChainConfig& b) {
    return a.chain_id == b.chain_id && a.homestead_block == b.homestead_block &&
           a.tangerine_whistle_block == b.tangerine_whistle_block &&
           a.spurious_dragon_block == b.spurious_dragon_block && a.byzantium_block == b.byzantium_block &&
           a.constantinople_block == b.constantinople_block && a.petersburg_block == b.petersburg_block &&
           a.istanbul_block == b.istanbul_block && a.muir_glacier_block == b.muir_glacier_block &&
           a.berlin_block == b.berlin_block && a.dao_block == b.dao_block;
}

}  // namespace silkworm
