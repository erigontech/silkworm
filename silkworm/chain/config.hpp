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

#ifndef SILKWORM_CHAIN_CONFIG_H_
#define SILKWORM_CHAIN_CONFIG_H_

#include <stdint.h>

#include <optional>

namespace silkworm {

struct ChainConfig {
    // https://eips.ethereum.org/EIPS/eip-155
    uint64_t chain_id{0};

    // https://eips.ethereum.org/EIPS/eip-606
    std::optional<uint64_t> homestead_block;

    // https://eips.ethereum.org/EIPS/eip-608
    // https://ecips.ethereumclassic.org/ECIPs/ecip-1015
    std::optional<uint64_t> tangerine_whistle_block;

    // TODO[ETC] EIP-160 was applied to ETC before the rest of Spurious Dragon; see
    // https://ecips.ethereumclassic.org/ECIPs/ecip-1066

    // https://eips.ethereum.org/EIPS/eip-607
    // https://ecips.ethereumclassic.org/ECIPs/ecip-1054
    std::optional<uint64_t> spurious_dragon_block;

    // https://eips.ethereum.org/EIPS/eip-609
    // https://ecips.ethereumclassic.org/ECIPs/ecip-1054
    std::optional<uint64_t> byzantium_block;

    // https://eips.ethereum.org/EIPS/eip-1013
    // https://ecips.ethereumclassic.org/ECIPs/ecip-1056
    std::optional<uint64_t> constantinople_block;

    // https://eips.ethereum.org/EIPS/eip-1716
    // https://ecips.ethereumclassic.org/ECIPs/ecip-1056
    std::optional<uint64_t> petersburg_block;

    // https://eips.ethereum.org/EIPS/eip-1679
    // https://ecips.ethereumclassic.org/ECIPs/ecip-1088
    std::optional<uint64_t> istanbul_block;

    // https://eips.ethereum.org/EIPS/eip-2387
    std::optional<uint64_t> muir_glacier_block;

    // https://eips.ethereum.org/EIPS/eip-779
    std::optional<uint64_t> dao_block;

    // Yellow Paper, Appendix K "Anomalies on the Main Network"
    std::optional<uint64_t> ripemd_deletion_block;

    // TODO[ETC] ECIP-1017

    bool has_homestead(uint64_t block_num) const noexcept {
        return homestead_block.has_value() && homestead_block <= block_num;
    }

    bool has_tangerine_whistle(uint64_t block_num) const noexcept {
        return tangerine_whistle_block.has_value() && tangerine_whistle_block <= block_num;
    }

    bool has_spurious_dragon(uint64_t block_num) const noexcept {
        return spurious_dragon_block.has_value() && spurious_dragon_block <= block_num;
    }

    bool has_byzantium(uint64_t block_num) const noexcept {
        return byzantium_block.has_value() && byzantium_block <= block_num;
    }

    bool has_constantinople(uint64_t block_num) const noexcept {
        return constantinople_block.has_value() && constantinople_block <= block_num;
    }

    bool has_petersburg(uint64_t block_num) const noexcept {
        return petersburg_block.has_value() && petersburg_block <= block_num;
    }

    bool has_istanbul(uint64_t block_num) const noexcept {
        return istanbul_block.has_value() && istanbul_block <= block_num;
    }

    bool has_muir_glacier(uint64_t block_num) const noexcept {
        return muir_glacier_block.has_value() && muir_glacier_block <= block_num;
    }
};

constexpr ChainConfig kMainnetConfig{
    1,  // chain_id

    1'150'000,  // homestead_block
    2'463'000,  // tangerine_whistle_block
    2'675'000,  // spurious_dragon_block
    4'370'000,  // byzantium_block
    7'280'000,  // constantinople_block
    7'280'000,  // petersburg_block
    9'069'000,  // istanbul_block
    9'200'000,  // muir_glacier_block

    1'920'000,  // dao_block
    2'675'119,  // ripemd_deletion_block
};

constexpr ChainConfig kRopstenConfig{
    3,  // chain_id

    0,          // homestead_block
    0,          // tangerine_whistle_block
    10,         // spurious_dragon_block
    1'700'000,  // byzantium_block
    4'230'000,  // constantinople_block
    4'939'394,  // petersburg_block
    6'485'846,  // istanbul_block
    7'117'117,  // muir_glacier_block
};

// https://ecips.ethereumclassic.org/ECIPs/ecip-1066
constexpr ChainConfig kClassicMainnetConfig{
    61,  // chain_id

    1'150'000,   // homestead_block
    2'500'000,   // tangerine_whistle_block
    8'772'000,   // spurious_dragon_block
    8'772'000,   // byzantium_block
    9'573'000,   // constantinople_block
    9'573'000,   // petersburg_block
    10'500'839,  // istanbul_block
};
}  // namespace silkworm

#endif  // SILKWORM_CHAIN_CONFIG_H_
