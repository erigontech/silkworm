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

#include <cstdint>
#include <map>
#include <optional>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <evmc/evmc.h>
#include <intx/intx.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/chain/config_map.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/protocol/bor_config.hpp>

namespace silkworm {

namespace protocol {

    //! \see EthashRuleSet
    struct EthashConfig {
        bool validate_seal{true};

        bool operator==(const EthashConfig&) const = default;
    };

    //! \see CliqueRuleSet
    struct CliqueConfig {
        bool operator==(const CliqueConfig&) const = default;
    };

    //! \see IRuleSet
    using RuleSetConfig = std::variant<EthashConfig, CliqueConfig, BorConfig>;

}  // namespace protocol

using ChainId = uint64_t;

struct ChainConfig {
    //! \brief Returns the chain identifier
    //! \see https://eips.ethereum.org/EIPS/eip-155
    ChainId chain_id{0};

    //! \brief Holds the hash of genesis block
    std::optional<evmc::bytes32> genesis_hash;

    // https://github.com/ethereum/execution-specs/tree/master/network-upgrades/mainnet-upgrades
    std::optional<BlockNum> homestead_block{std::nullopt};
    std::optional<BlockNum> dao_block{std::nullopt};
    std::optional<BlockNum> tangerine_whistle_block{std::nullopt};
    std::optional<BlockNum> spurious_dragon_block{std::nullopt};
    std::optional<BlockNum> byzantium_block{std::nullopt};
    std::optional<BlockNum> constantinople_block{std::nullopt};
    std::optional<BlockNum> petersburg_block{std::nullopt};
    std::optional<BlockNum> istanbul_block{std::nullopt};
    std::optional<BlockNum> muir_glacier_block{std::nullopt};
    std::optional<BlockNum> berlin_block{std::nullopt};
    std::optional<BlockNum> london_block{std::nullopt};

    // (Optional) contract where EIP-1559 fees will be sent to that otherwise would be burnt since the London fork
    ConfigMap<evmc::address> burnt_contract{};

    std::optional<BlockNum> arrow_glacier_block{std::nullopt};
    std::optional<BlockNum> gray_glacier_block{std::nullopt};

    //! \brief PoW to PoS switch
    //! \see EIP-3675: Upgrade consensus to Proof-of-Stake
    std::optional<intx::uint256> terminal_total_difficulty{std::nullopt};
    std::optional<BlockNum> merge_netsplit_block{std::nullopt};  // FORK_NEXT_VALUE in EIP-3675

    // Starting from Shanghai, forks are triggered by block time rather than number
    std::optional<BlockTime> shanghai_time{std::nullopt};
    std::optional<BlockTime> cancun_time{std::nullopt};

    //! \brief Returns the config of the (pre-Merge) protocol rule set
    protocol::RuleSetConfig rule_set_config{protocol::EthashConfig{.validate_seal = false}};

    //! \brief Returns the revision level at given block number
    //! \details In other words, on behalf of Json chain config data
    //! returns whether specific HF have occurred
    [[nodiscard]] evmc_revision revision(BlockNum block_number, uint64_t block_time) const noexcept;

    [[nodiscard]] std::vector<BlockNum> distinct_fork_numbers() const;
    [[nodiscard]] std::vector<BlockTime> distinct_fork_times() const;
    [[nodiscard]] std::vector<uint64_t> distinct_fork_points() const;

    //! \brief Return the JSON representation of this object
    [[nodiscard]] nlohmann::json to_json() const noexcept;

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
    //! \brief Try parse a JSON object into strongly typed ChainConfig
    //! \remark Should this return std::nullopt the parsing has failed
    static std::optional<ChainConfig> from_json(const nlohmann::json& json) noexcept;

    friend bool operator==(const ChainConfig&, const ChainConfig&) = default;
};

std::ostream& operator<<(std::ostream& out, const ChainConfig& obj);

inline constexpr evmc::bytes32 kMainnetGenesisHash{0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3_bytes32};
SILKWORM_CONSTINIT extern const ChainConfig kMainnetConfig;

inline constexpr evmc::bytes32 kGoerliGenesisHash{0xbf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a_bytes32};
SILKWORM_CONSTINIT extern const ChainConfig kGoerliConfig;

inline constexpr evmc::bytes32 kSepoliaGenesisHash{0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9_bytes32};
SILKWORM_CONSTINIT extern const ChainConfig kSepoliaConfig;

inline constexpr evmc::bytes32 kPolygonGenesisHash{0xa9c28ce2141b56c474f1dc504bee9b01eb1bd7d1a507580d5519d4437a97de1b_bytes32};
extern const ChainConfig kPolygonConfig;

inline constexpr evmc::bytes32 kMumbaiGenesisHash{0x7b66506a9ebdbf30d32b43c5f15a3b1216269a1ec3a75aa3182b86176a2b1ca7_bytes32};
extern const ChainConfig kMumbaiConfig;

//! \brief Looks up a known chain config provided its chain ID
std::optional<std::pair<const std::string, const ChainConfig*>> lookup_known_chain(uint64_t chain_id) noexcept;

//! \brief Looks up a known chain config provided its chain identifier (eg. "mainnet")
std::optional<std::pair<const std::string, const ChainConfig*>> lookup_known_chain(std::string_view identifier) noexcept;

//! \brief Returns a map known chains names mapped to their respective chain ids
std::map<std::string, uint64_t> get_known_chains_map() noexcept;

}  // namespace silkworm
