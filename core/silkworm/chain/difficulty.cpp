/*
   Copyright 2020 The Silkworm Authors

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

#include "difficulty.hpp"

namespace silkworm {

intx::uint256 canonical_difficulty(uint64_t block_number, const uint64_t block_timestamp,
                                   const intx::uint256& parent_difficulty, const uint64_t parent_timestamp,
                                   const bool parent_has_uncles, const ChainConfig& config) {
    const evmc_revision rev{config.revision(block_number)};

    intx::uint256 difficulty{parent_difficulty};

    const intx::uint256 x{parent_difficulty >> 11};  // parent_difficulty / 2048;

    if (rev >= EVMC_BYZANTIUM) {
        difficulty -= x * 99;

        // https://eips.ethereum.org/EIPS/eip-100
        const uint64_t y{parent_has_uncles ? 2u : 1u};
        const uint64_t z{(block_timestamp - parent_timestamp) / 9};
        if (99 + y > z) {
            difficulty += (99 + y - z) * x;
        }
    } else if (rev >= EVMC_HOMESTEAD) {
        difficulty -= x * 99;

        const uint64_t z{(block_timestamp - parent_timestamp) / 10};
        if (100 > z) {
            difficulty += (100 - z) * x;
        }
    } else {
        if (block_timestamp - parent_timestamp < 13) {
            difficulty += x;
        } else {
            difficulty -= x;
        }
    }

    uint64_t bomb_delay{0};
    if (config.arrow_glacier_block.has_value() && block_number >= config.arrow_glacier_block) {
        // https://eips.ethereum.org/EIPS/eip-4345
        bomb_delay = 10'700'000;
    } else if (rev >= EVMC_LONDON) {
        // https://eips.ethereum.org/EIPS/eip-3554
        bomb_delay = 9'700'000;
    } else if (config.muir_glacier_block.has_value() && block_number >= config.muir_glacier_block) {
        // https://eips.ethereum.org/EIPS/eip-2384
        bomb_delay = 9'000'000;
    } else if (rev >= EVMC_CONSTANTINOPLE) {
        // https://eips.ethereum.org/EIPS/eip-1234
        bomb_delay = 5'000'000;
    } else if (rev >= EVMC_BYZANTIUM) {
        // https://eips.ethereum.org/EIPS/eip-649
        bomb_delay = 3'000'000;
    }

    if (block_number > bomb_delay) {
        block_number -= bomb_delay;
    } else {
        block_number = 0;
    }

    const uint64_t n{block_number / 100'000};
    if (n >= 2) {
        static constexpr intx::uint256 one{1};
        difficulty += one << (n - 2);
    }

    if (difficulty < kMinDifficulty) {
        difficulty = kMinDifficulty;
    }
    return difficulty;
}

}  // namespace silkworm
