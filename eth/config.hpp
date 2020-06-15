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

#ifndef SILKWORM_ETH_CONFIG_H_
#define SILKWORM_ETH_CONFIG_H_

#include <stdint.h>

#include <optional>

namespace silkworm::eth {

struct ChainConfig {
  // https://eips.ethereum.org/EIPS/eip-155
  uint64_t chain_id{0};

  // https://eips.ethereum.org/EIPS/eip-2
  std::optional<uint64_t> homestead_block;

  // https://eips.ethereum.org/EIPS/eip-779
  std::optional<uint64_t> dao_block;

  // https://eips.ethereum.org/EIPS/eip-608
  std::optional<uint64_t> tangerine_whistle_block;

  // https://eips.ethereum.org/EIPS/eip-607
  std::optional<uint64_t> spurious_dragon_block;

  // https://eips.ethereum.org/EIPS/eip-609
  std::optional<uint64_t> byzantium_block;

  // https://eips.ethereum.org/EIPS/eip-1013
  std::optional<uint64_t> constantinople_block;

  // https://eips.ethereum.org/EIPS/eip-1716
  std::optional<uint64_t> petersburg_block;

  // https://eips.ethereum.org/EIPS/eip-1679
  std::optional<uint64_t> istanbul_block;

  // https://eips.ethereum.org/EIPS/eip-2387
  std::optional<uint64_t> muir_glacier_block;
};

constexpr ChainConfig kMainnetChainConfig{
    .chain_id = 1,

    .homestead_block = 1150000,
    .dao_block = 1920000,
    .tangerine_whistle_block = 2463000,
    .spurious_dragon_block = 2675000,
    .byzantium_block = 4370000,
    .constantinople_block = 7280000,
    .petersburg_block = 7280000,
    .istanbul_block = 9069000,
    .muir_glacier_block = 9200000,
};
}  // namespace silkworm::eth

#endif  // SILKWORM_ETH_CONFIG_H_
