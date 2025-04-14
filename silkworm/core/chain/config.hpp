// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/small_map.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/protocol/bor/config.hpp>
#include <silkworm/core/protocol/ethash_config.hpp>

namespace silkworm {

namespace protocol {

    // Already merged at genesis
    struct NoPreMergeConfig {
        bool operator==(const NoPreMergeConfig&) const = default;
    };

    //! \see IRuleSet
    using PreMergeRuleSetConfig = std::variant<NoPreMergeConfig, EthashConfig, bor::Config>;

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
    SmallMap<BlockNum, evmc::address> burnt_contract{};

    std::optional<BlockNum> arrow_glacier_block{std::nullopt};
    std::optional<BlockNum> gray_glacier_block{std::nullopt};

    //! \brief PoW to PoS switch
    //! \see EIP-3675: Upgrade consensus to Proof-of-Stake
    std::optional<intx::uint256> terminal_total_difficulty{std::nullopt};
    std::optional<BlockNum> merge_netsplit_block{std::nullopt};  // FORK_NEXT_VALUE in EIP-3675

    // Starting from Shanghai, forks are triggered by block time rather than number
    std::optional<BlockTime> shanghai_time{std::nullopt};
    std::optional<BlockTime> cancun_time{std::nullopt};
    std::optional<BlockTime> prague_time{std::nullopt};

    //! \brief Returns the config of the (pre-Merge) protocol rule set
    protocol::PreMergeRuleSetConfig rule_set_config{protocol::NoPreMergeConfig{}};

    // The Shanghai hard fork has withdrawals, but Agra does not
    bool withdrawals_activated(BlockTime block_time) const noexcept;
    bool is_london(BlockNum block_num) const noexcept;
    bool is_prague(BlockNum block_num, BlockTime block_time) const noexcept;

    //! \brief Returns the revision level at given block number
    //! \details In other words, on behalf of Json chain config data
    //! returns whether specific HF have occurred
    evmc_revision revision(BlockNum block_num, uint64_t block_time) const noexcept;

    std::vector<BlockNum> distinct_fork_block_nums() const;
    std::vector<BlockTime> distinct_fork_times() const;
    std::vector<uint64_t> distinct_fork_points() const;

    //! \brief Check invariant on pre-Merge config validity
    bool valid_pre_merge_config() const noexcept;

    //! \brief Return the JSON representation of this object
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
    //! \brief Try parse a JSON object into strongly typed ChainConfig
    //! \remark Should this return std::nullopt the parsing has failed
    static std::optional<ChainConfig> from_json(const nlohmann::json& json) noexcept;

    friend bool operator==(const ChainConfig&, const ChainConfig&) = default;
};

std::ostream& operator<<(std::ostream& out, const ChainConfig& obj);

using namespace evmc::literals;

inline constexpr evmc::bytes32 kMainnetGenesisHash{0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3_bytes32};
constinit extern const ChainConfig kMainnetConfig;

inline constexpr evmc::bytes32 kHoleskyGenesisHash{0xb5f7f912443c940f21fd611f12828d75b534364ed9e95ca4e307729a4661bde4_bytes32};
constinit extern const ChainConfig kHoleskyConfig;

inline constexpr evmc::bytes32 kSepoliaGenesisHash{0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9_bytes32};
constinit extern const ChainConfig kSepoliaConfig;

inline constexpr evmc::bytes32 kBorMainnetGenesisHash{0xa9c28ce2141b56c474f1dc504bee9b01eb1bd7d1a507580d5519d4437a97de1b_bytes32};
constinit extern const ChainConfig kBorMainnetConfig;

inline constexpr evmc::bytes32 kAmoyGenesisHash{0x7202b2b53c5a0836e773e319d18922cc756dd67432f9a1f65352b61f4406c697_bytes32};
constinit extern const ChainConfig kAmoyConfig;

//! \brief Known chain names mapped to their respective chain IDs
inline constexpr SmallMap<std::string_view, ChainId> kKnownChainNameToId{
    {"amoy", 80002},
    {"bor-mainnet", 137},
    {"holesky", 17000},
    {"mainnet", 1},
    {"sepolia", 11155111},
};

//! \brief Known chain IDs mapped to their respective chain configs
inline constexpr SmallMap<ChainId, const ChainConfig*> kKnownChainConfigs{
    {*kKnownChainNameToId.find("mainnet"), &kMainnetConfig},
    {*kKnownChainNameToId.find("amoy"), &kAmoyConfig},
    {*kKnownChainNameToId.find("bor-mainnet"), &kBorMainnetConfig},
    {*kKnownChainNameToId.find("holesky"), &kHoleskyConfig},
    {*kKnownChainNameToId.find("sepolia"), &kSepoliaConfig},
};

}  // namespace silkworm
