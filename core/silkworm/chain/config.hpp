/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_CHAIN_CONFIG_HPP_
#define SILKWORM_CHAIN_CONFIG_HPP_

#include <stdint.h>

#include <array>
#include <optional>

#include <evmc/evmc.h>
#include <nlohmann/json.hpp>

namespace silkworm {

enum class SealEngineType {
    kNoProof,
    kEthash,
    kClique,
    kAuRA,
};

struct ChainConfig {
    static constexpr const char* kJsonForkNames[]{
        "homesteadBlock",  // EVMC_HOMESTEAD
        // there's no evmc_revision for daoForkBlock
        "eip150Block",          // EVMC_TANGERINE_WHISTLE
        "eip155Block",          // EVMC_SPURIOUS_DRAGON
        "byzantiumBlock",       // EVMC_BYZANTIUM
        "constantinopleBlock",  // EVMC_CONSTANTINOPLE
        "petersburgBlock",      // EVMC_PETERSBURG
        "istanbulBlock",        // EVMC_ISTANBUL
        // there's no evmc_revision for muirGlacierBlock
        "berlinBlock",    // EVMC_BERLIN
        "londonBlock",    // EVMC_LONDON
        "shanghaiBlock",  // EVMC_SHANGHAI
    };

    static_assert(std::size(kJsonForkNames) == EVMC_MAX_REVISION);

    // https://eips.ethereum.org/EIPS/eip-155
    uint64_t chain_id{0};

    SealEngineType seal_engine{SealEngineType::kNoProof};

    // Block numbers of forks that have an evmc_revision value
    std::array<std::optional<uint64_t>, EVMC_MAX_REVISION> fork_blocks{};

    // https://eips.ethereum.org/EIPS/eip-2387
    std::optional<uint64_t> muir_glacier_block{std::nullopt};

    // https://eips.ethereum.org/EIPS/eip-779
    std::optional<uint64_t> dao_block{std::nullopt};

    // Returns the revision level at given block number
    // In other words, on behalf of Json chain config data
    // returns whether or not specific HF have occurred
    evmc_revision revision(uint64_t block_number) const noexcept;

    // As ancillary to revision this returns at which block
    // a specific revision has occurred. If return value is std::nullopt
    // it means the actual chain either does not support such revision
    std::optional<uint64_t> revision_block(evmc_revision rev) const noexcept;

    void set_revision_block(evmc_revision rev, std::optional<uint64_t> block);

    nlohmann::json to_json() const noexcept;

    /*Sample JSON input:
    {
            "chainId":1,
            "homesteadBlock":1150000,
            "daoForkBlock":1920000,
            "eip150Block":2463000,
            "eip155Block":2675000,
            "byzantiumBlock":4370000,
            "constantinopleBlock":7280000,
            "petersburgBlock":7280000,
            "istanbulBlock":9069000,
            "muirGlacierBlock":9200000,
            "berlinBlock":12244000
    }
    */
    static std::optional<ChainConfig> from_json(const nlohmann::json& json) noexcept;
};

bool operator==(const ChainConfig& a, const ChainConfig& b);

std::ostream& operator<<(std::ostream& out, const ChainConfig& obj);

constexpr ChainConfig kMainnetConfig{
    1,  // chain_id
    SealEngineType::kEthash,
    {
        1'150'000,   // Homestead
        2'463'000,   // Tangerine Whistle
        2'675'000,   // Spurious Dragon
        4'370'000,   // Byzantium
        7'280'000,   // Constantinople
        7'280'000,   // Petersburg
        9'069'000,   // Istanbul
        12'244'000,  // Berlin
        12'965'000,  // London
    },

    9'200'000,  // muir_glacier_block
    1'920'000,  // dao_block
};

constexpr ChainConfig kRopstenConfig{
    3,  // chain_id
    SealEngineType::kEthash,
    {
        0,           // Homestead
        0,           // Tangerine Whistle
        10,          // Spurious Dragon
        1'700'000,   // Byzantium
        4'230'000,   // Constantinople
        4'939'394,   // Petersburg
        6'485'846,   // Istanbul
        9'812'189,   // Berlin
        10'499'401,  // London
    },

    7'117'117,  // muir_glacier_block
};

constexpr ChainConfig kRinkebyConfig{
    4,  // chain_id
    SealEngineType::kClique,
    {
        1,          // Homestead
        2,          // Tangerine Whistle
        3,          // Spurious Dragon
        1'035'301,  // Byzantium
        3'660'663,  // Constantinople
        4'321'234,  // Petersburg
        5'435'345,  // Istanbul
        8'290'928,  // Berlin
        8'897'988,  // London
    },
};

constexpr ChainConfig kGoerliConfig{
    5,  // chain_id
    SealEngineType::kClique,
    {
        0,          // Homestead
        0,          // Tangerine Whistle
        0,          // Spurious Dragon
        0,          // Byzantium
        0,          // Constantinople
        0,          // Petersburg
        1'561'651,  // Istanbul
        4'460'644,  // Berlin
        5'062'605,  // London
    },
};

inline const ChainConfig* lookup_chain_config(uint64_t chain_id) noexcept {
    switch (chain_id) {
        case kMainnetConfig.chain_id:
            return &kMainnetConfig;
        case kRopstenConfig.chain_id:
            return &kRopstenConfig;
        case kRinkebyConfig.chain_id:
            return &kRinkebyConfig;
        case kGoerliConfig.chain_id:
            return &kGoerliConfig;
        default:
            return nullptr;
    }
}

}  // namespace silkworm

#endif  // SILKWORM_CHAIN_CONFIG_HPP_
