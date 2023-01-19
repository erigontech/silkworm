/*
   Copyright 2022 The Silkworm Authors

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

#pragma once

#include <silkworm/types/block.hpp>
#include <silkworm/types/receipt.hpp>

namespace silkworm::test {

/// Always Frontier rules.
inline constexpr ChainConfig kFrontierConfig{
    .chain_id = 1,
    .seal_engine = SealEngineType::kNoProof,
};

/// Enables London from genesis.
inline constexpr ChainConfig kLondonConfig{
    .chain_id = 1,
    .seal_engine = SealEngineType::kNoProof,
    .homestead_block = 0,
    .tangerine_whistle_block = 0,
    .spurious_dragon_block = 0,
    .byzantium_block = 0,
    .constantinople_block = 0,
    .petersburg_block = 0,
    .istanbul_block = 0,
    .muir_glacier_block = 0,
    .berlin_block = 0,
    .london_block = 0,
};

/// Enables Shanghai from genesis.
inline constexpr ChainConfig kShanghaiConfig{
    .chain_id = 1,
    .seal_engine = SealEngineType::kNoProof,
    .homestead_block = 0,
    .tangerine_whistle_block = 0,
    .spurious_dragon_block = 0,
    .byzantium_block = 0,
    .constantinople_block = 0,
    .petersburg_block = 0,
    .istanbul_block = 0,
    .muir_glacier_block = 0,
    .berlin_block = 0,
    .london_block = 0,
    .arrow_glacier_block = 0,
    .gray_glacier_block = 0,
    .terminal_total_difficulty = 0,
    .shanghai_time = 0,
};

std::vector<Transaction> sample_transactions();
std::vector<Receipt> sample_receipts();

}  // namespace silkworm::test
