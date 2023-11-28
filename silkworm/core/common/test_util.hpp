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

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/receipt.hpp>
#include <silkworm/core/types/transaction.hpp>

namespace silkworm::test {

//! Always Frontier rules.
inline constexpr ChainConfig kFrontierConfig{
    .chain_id = 1,
};

//! Enables London from genesis.
inline constexpr ChainConfig kLondonConfig{
    .chain_id = 1,
    .homestead_block = 0,
    .tangerine_whistle_block = 0,
    .spurious_dragon_block = 0,
    .byzantium_block = 0,
    .constantinople_block = 0,
    .petersburg_block = 0,
    .istanbul_block = 0,
    .berlin_block = 0,
    .london_block = 0,
};

//! Enables Shanghai from genesis.
inline constexpr ChainConfig kShanghaiConfig{
    .chain_id = 1,
    .homestead_block = 0,
    .tangerine_whistle_block = 0,
    .spurious_dragon_block = 0,
    .byzantium_block = 0,
    .constantinople_block = 0,
    .petersburg_block = 0,
    .istanbul_block = 0,
    .berlin_block = 0,
    .london_block = 0,
    .terminal_total_difficulty = 0,
    .shanghai_time = 0,
};

inline const std::map<std::string, ChainConfig> kNetworkConfig{
    {"Frontier", test::kFrontierConfig},
    {"Homestead",
     {
         .chain_id = 1,
         .homestead_block = 0,
     }},
    {"FrontierToHomesteadAt5",
     {
         .chain_id = 1,
         .homestead_block = 5,
     }},
    {"HomesteadToDaoAt5",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .dao_block = 5,
     }},
    {"EIP150",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
     }},
    {"HomesteadToEIP150At5",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 5,
     }},
    {"EIP158",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
     }},
    {"Byzantium",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
     }},
    {"EIP158ToByzantiumAt5",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 5,
     }},
    {"Constantinople",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
     }},
    {"ConstantinopleFix",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
     }},
    {"ByzantiumToConstantinopleFixAt5",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 5,
         .petersburg_block = 5,
     }},
    {"Istanbul",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
     }},
    {"EIP2384",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .muir_glacier_block = 0,
     }},
    {"Berlin",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .muir_glacier_block = 0,
         .berlin_block = 0,
     }},
    {"London", test::kLondonConfig},
    {"BerlinToLondonAt5",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .muir_glacier_block = 0,
         .berlin_block = 0,
         .london_block = 5,
     }},
    {"ArrowGlacier",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .berlin_block = 0,
         .london_block = 0,
         .arrow_glacier_block = 0,
     }},
    {"GrayGlacier",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .berlin_block = 0,
         .london_block = 0,
         .gray_glacier_block = 0,
     }},
    {"Merge",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .berlin_block = 0,
         .london_block = 0,
         .terminal_total_difficulty = 0,
     }},
    {"ArrowGlacierToMergeAtDiffC0000",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .berlin_block = 0,
         .london_block = 0,
         .arrow_glacier_block = 0,
         .terminal_total_difficulty = 0xC0000,
     }},
    {"Shanghai", test::kShanghaiConfig},
    {"MergeToShanghaiAtTime15k",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .berlin_block = 0,
         .london_block = 0,
         .terminal_total_difficulty = 0,
         .shanghai_time = 15'000,
     }},
    {"Cancun",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .berlin_block = 0,
         .london_block = 0,
         .terminal_total_difficulty = 0,
         .shanghai_time = 0,
         .cancun_time = 0,
     }},
    {"ShanghaiToCancunAtTime15k",
     {
         .chain_id = 1,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .berlin_block = 0,
         .london_block = 0,
         .terminal_total_difficulty = 0,
         .shanghai_time = 0,
         .cancun_time = 15'000,
     }},
};

std::vector<Transaction> sample_transactions();
std::vector<Receipt> sample_receipts();

}  // namespace silkworm::test
