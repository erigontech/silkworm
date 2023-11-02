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

#include "config.hpp"

#include <algorithm>
#include <functional>
#include <set>
#include <string>

#include <silkworm/core/common/as_range.hpp>
#include <silkworm/core/common/overloaded.hpp>
#include <silkworm/core/execution/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

static const std::vector<std::pair<std::string, const ChainConfig*>> kKnownChainConfigs{
    {"mainnet", &kMainnetConfig},
    {"goerli", &kGoerliConfig},
    {"sepolia", &kSepoliaConfig},
    {"polygon", &kPolygonConfig},
    {"mumbai", &kMumbaiConfig},
};

constexpr const char* kTerminalTotalDifficulty{"terminalTotalDifficulty"};

static inline void member_to_json(nlohmann::json& json, const std::string& key, const std::optional<uint64_t>& source) {
    if (source) {
        json[key] = source.value();
    }
}

static inline void read_json_config_member(const nlohmann::json& json, const std::string& key,
                                           std::optional<uint64_t>& target) {
    if (json.contains(key)) {
        target = json[key].get<uint64_t>();
    }
}

nlohmann::json ChainConfig::to_json() const noexcept {
    nlohmann::json ret;

    ret["chainId"] = chain_id;

    nlohmann::json empty_object(nlohmann::json::value_t::object);
    std::visit(
        Overloaded{
            [&](const protocol::EthashConfig& x) { if (x.validate_seal) ret.emplace("ethash", empty_object); },
            [&](const protocol::CliqueConfig&) { ret.emplace("clique", empty_object); },
            [&](const protocol::BorConfig& x) { ret.emplace("bor", x.to_json()); },
        },
        rule_set_config);

    member_to_json(ret, "homesteadBlock", homestead_block);
    member_to_json(ret, "daoForkBlock", dao_block);
    member_to_json(ret, "eip150Block", tangerine_whistle_block);
    member_to_json(ret, "eip155Block", spurious_dragon_block);
    member_to_json(ret, "byzantiumBlock", byzantium_block);
    member_to_json(ret, "constantinopleBlock", constantinople_block);
    member_to_json(ret, "petersburgBlock", petersburg_block);
    member_to_json(ret, "istanbulBlock", istanbul_block);
    member_to_json(ret, "muirGlacierBlock", muir_glacier_block);
    member_to_json(ret, "berlinBlock", berlin_block);
    member_to_json(ret, "londonBlock", london_block);

    if (!burnt_contract.empty()) {
        nlohmann::json burnt_contract_json = nlohmann::json::object();
        for (const auto& [from, contract] : burnt_contract) {
            burnt_contract_json[std::to_string(from)] = address_to_hex(contract);
        }
        ret["burntContract"] = burnt_contract_json;
    }

    member_to_json(ret, "arrowGlacierBlock", arrow_glacier_block);
    member_to_json(ret, "grayGlacierBlock", gray_glacier_block);

    if (terminal_total_difficulty) {
        // TODO(yperbasis): geth probably treats terminalTotalDifficulty as a JSON number
        ret[kTerminalTotalDifficulty] = to_string(*terminal_total_difficulty);
    }

    member_to_json(ret, "mergeNetsplitBlock", merge_netsplit_block);
    member_to_json(ret, "shanghaiTime", shanghai_time);
    member_to_json(ret, "cancunTime", cancun_time);

    if (genesis_hash.has_value()) {
        ret["genesisBlockHash"] = to_hex(*genesis_hash, /*with_prefix=*/true);
    }

    return ret;
}

std::optional<ChainConfig> ChainConfig::from_json(const nlohmann::json& json) noexcept {
    if (json.is_discarded() || !json.contains("chainId") || !json["chainId"].is_number()) {
        return std::nullopt;
    }

    ChainConfig config{};
    config.chain_id = json["chainId"].get<uint64_t>();

    if (json.contains("ethash")) {
        config.rule_set_config = protocol::EthashConfig{};
    } else if (json.contains("clique")) {
        config.rule_set_config = protocol::CliqueConfig{};
    } else if (json.contains("bor")) {
        std::optional<protocol::BorConfig> bor_config{protocol::BorConfig::from_json(json["bor"])};
        if (!bor_config) {
            return std::nullopt;
        }
        config.rule_set_config = *bor_config;
    } else {
        config.rule_set_config = protocol::EthashConfig{.validate_seal = false};
    }

    read_json_config_member(json, "homesteadBlock", config.homestead_block);
    read_json_config_member(json, "daoForkBlock", config.dao_block);
    read_json_config_member(json, "eip150Block", config.tangerine_whistle_block);
    read_json_config_member(json, "eip155Block", config.spurious_dragon_block);
    read_json_config_member(json, "byzantiumBlock", config.byzantium_block);
    read_json_config_member(json, "constantinopleBlock", config.constantinople_block);
    read_json_config_member(json, "petersburgBlock", config.petersburg_block);
    read_json_config_member(json, "istanbulBlock", config.istanbul_block);
    read_json_config_member(json, "muirGlacierBlock", config.muir_glacier_block);
    read_json_config_member(json, "berlinBlock", config.berlin_block);
    read_json_config_member(json, "londonBlock", config.london_block);

    if (json.contains("burntContract")) {
        std::vector<std::pair<BlockNum, evmc::address>> burnt_contract;
        for (const auto& item : json["burntContract"].items()) {
            const BlockNum from{std::stoull(item.key(), nullptr, 0)};
            const evmc::address contract{hex_to_address(item.value().get<std::string>())};
            burnt_contract.emplace_back(from, contract);
        }
        config.burnt_contract = ConfigMap<evmc::address>(burnt_contract.begin(), burnt_contract.end());
    }

    read_json_config_member(json, "arrowGlacierBlock", config.arrow_glacier_block);
    read_json_config_member(json, "grayGlacierBlock", config.gray_glacier_block);

    if (json.contains(kTerminalTotalDifficulty)) {
        // We handle terminalTotalDifficulty serialized both as JSON string *and* as JSON number
        if (json[kTerminalTotalDifficulty].is_string()) {
            /* This is still present to maintain compatibility with previous Silkworm format */
            config.terminal_total_difficulty =
                intx::from_string<intx::uint256>(json[kTerminalTotalDifficulty].get<std::string>());
        } else if (json[kTerminalTotalDifficulty].is_number()) {
            /* This is for compatibility with Erigon that uses a JSON number */
            // nlohmann::json treats JSON numbers that overflow 64-bit unsigned integer as floating-point numbers and
            // intx::uint256 cannot currently be constructed from a floating-point number or string in scientific notation
            config.terminal_total_difficulty =
                from_string_sci<intx::uint256>(json[kTerminalTotalDifficulty].dump().c_str());
        }
    }

    read_json_config_member(json, "mergeNetsplitBlock", config.merge_netsplit_block);
    read_json_config_member(json, "shanghaiTime", config.shanghai_time);
    read_json_config_member(json, "cancunTime", config.cancun_time);

    /* Note ! genesis_hash is purposely omitted. It must be loaded from db after the
     * effective genesis block has been persisted */

    return config;
}

[[nodiscard]] bool ChainConfig::withdrawals_activated(uint64_t block_time) const noexcept {
    return shanghai_time && block_time >= shanghai_time;
}

evmc_revision ChainConfig::revision(uint64_t block_number, uint64_t block_time) const noexcept {
    if (cancun_time && block_time >= cancun_time) return EVMC_CANCUN;
    if (shanghai_time && block_time >= shanghai_time) return EVMC_SHANGHAI;

    const protocol::BorConfig* bor{std::get_if<protocol::BorConfig>(&rule_set_config)};
    if (bor && bor->agra_block && block_number >= bor->agra_block) return EVMC_SHANGHAI;

    if (london_block && block_number >= london_block) return EVMC_LONDON;
    if (berlin_block && block_number >= berlin_block) return EVMC_BERLIN;
    if (istanbul_block && block_number >= istanbul_block) return EVMC_ISTANBUL;
    if (petersburg_block && block_number >= petersburg_block) return EVMC_PETERSBURG;
    if (constantinople_block && block_number >= constantinople_block) return EVMC_CONSTANTINOPLE;
    if (byzantium_block && block_number >= byzantium_block) return EVMC_BYZANTIUM;
    if (spurious_dragon_block && block_number >= spurious_dragon_block) return EVMC_SPURIOUS_DRAGON;
    if (tangerine_whistle_block && block_number >= tangerine_whistle_block) return EVMC_TANGERINE_WHISTLE;
    if (homestead_block && block_number >= homestead_block) return EVMC_HOMESTEAD;

    return EVMC_FRONTIER;
}

std::vector<BlockNum> ChainConfig::distinct_fork_numbers() const {
    std::set<BlockNum> ret;

    // Add forks identified by *block number* in ascending order
    ret.insert(homestead_block.value_or(0));
    ret.insert(dao_block.value_or(0));
    ret.insert(tangerine_whistle_block.value_or(0));
    ret.insert(spurious_dragon_block.value_or(0));
    ret.insert(byzantium_block.value_or(0));
    ret.insert(constantinople_block.value_or(0));
    ret.insert(petersburg_block.value_or(0));
    ret.insert(istanbul_block.value_or(0));
    ret.insert(muir_glacier_block.value_or(0));
    ret.insert(berlin_block.value_or(0));
    ret.insert(london_block.value_or(0));
    ret.insert(arrow_glacier_block.value_or(0));
    ret.insert(gray_glacier_block.value_or(0));
    ret.insert(merge_netsplit_block.value_or(0));

    ret.erase(0);  // Block 0 is not a fork number
    return {ret.cbegin(), ret.cend()};
}

std::vector<BlockTime> ChainConfig::distinct_fork_times() const {
    std::set<BlockTime> ret;

    // Add forks identified by *block timestamp* in ascending order
    ret.insert(shanghai_time.value_or(0));
    ret.insert(cancun_time.value_or(0));

    ret.erase(0);  // Block 0 is not a fork timestamp
    return {ret.cbegin(), ret.cend()};
}

std::vector<uint64_t> ChainConfig::distinct_fork_points() const {
    auto numbers{distinct_fork_numbers()};
    auto times{distinct_fork_times()};

    std::vector<uint64_t> points;
    points.resize(numbers.size() + times.size());
    std::move(numbers.begin(), numbers.end(), points.begin());
    std::move(times.begin(), times.end(), points.begin() + (numbers.end() - numbers.begin()));

    return points;
}

std::ostream& operator<<(std::ostream& out, const ChainConfig& obj) { return out << obj.to_json(); }

std::optional<std::pair<const std::string, const ChainConfig*>> lookup_known_chain(const uint64_t chain_id) noexcept {
    auto it{
        as_range::find_if(kKnownChainConfigs, [&chain_id](const std::pair<std::string, const ChainConfig*>& x) -> bool {
            return x.second->chain_id == chain_id;
        })};

    if (it == kKnownChainConfigs.end()) {
        return std::nullopt;
    }
    return std::make_pair(it->first, it->second);
}

std::optional<std::pair<const std::string, const ChainConfig*>> lookup_known_chain(const std::string_view identifier) noexcept {
    auto it{
        as_range::find_if(kKnownChainConfigs, [&identifier](const std::pair<std::string, const ChainConfig*>& x) -> bool {
            return iequals(x.first, identifier);
        })};

    if (it == kKnownChainConfigs.end()) {
        return std::nullopt;
    }
    return std::make_pair(it->first, it->second);
}

// TODO(yperbasis): rework with constexpr maps
std::map<std::string, uint64_t> get_known_chains_map() noexcept {
    std::map<std::string, uint64_t> ret;
    as_range::for_each(kKnownChainConfigs, [&ret](const std::pair<std::string, const ChainConfig*>& x) -> void {
        ret[x.first] = x.second->chain_id;
    });
    return ret;
}

SILKWORM_CONSTINIT const ChainConfig kMainnetConfig{
    .chain_id = 1,
    .homestead_block = 1'150'000,
    .dao_block = 1'920'000,
    .tangerine_whistle_block = 2'463'000,
    .spurious_dragon_block = 2'675'000,
    .byzantium_block = 4'370'000,
    .constantinople_block = 7'280'000,
    .petersburg_block = 7'280'000,
    .istanbul_block = 9'069'000,
    .muir_glacier_block = 9'200'000,
    .berlin_block = 12'244'000,
    .london_block = 12'965'000,
    .arrow_glacier_block = 13'773'000,
    .gray_glacier_block = 15'050'000,
    .terminal_total_difficulty = intx::from_string<intx::uint256>("58750000000000000000000"),
    .shanghai_time = 1681338455,
    .rule_set_config = protocol::EthashConfig{},
};

SILKWORM_CONSTINIT const ChainConfig kGoerliConfig{
    .chain_id = 5,
    .homestead_block = 0,
    .tangerine_whistle_block = 0,
    .spurious_dragon_block = 0,
    .byzantium_block = 0,
    .constantinople_block = 0,
    .petersburg_block = 0,
    .istanbul_block = 1'561'651,
    .berlin_block = 4'460'644,
    .london_block = 5'062'605,
    .terminal_total_difficulty = 10790000,
    .shanghai_time = 1678832736,
    .rule_set_config = protocol::CliqueConfig{},
};

SILKWORM_CONSTINIT const ChainConfig kSepoliaConfig{
    .chain_id = 11155111,
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
    .terminal_total_difficulty = 17000000000000000,
    .merge_netsplit_block = 1'735'371,
    .shanghai_time = 1677557088,
    .rule_set_config = protocol::EthashConfig{},
};

const ChainConfig kPolygonConfig{
    .chain_id = 137,
    .homestead_block = 0,
    .tangerine_whistle_block = 0,
    .spurious_dragon_block = 0,
    .byzantium_block = 0,
    .constantinople_block = 0,
    .petersburg_block = 0,
    .istanbul_block = 3'395'000,
    .muir_glacier_block = 3'395'000,
    .berlin_block = 14'750'000,
    .london_block = 23'850'000,
    .burnt_contract = {
        {23'850'000, 0x70bca57f4579f58670ab2d18ef16e02c17553c38_address},
    },
    .rule_set_config = protocol::BorConfig{
        .period = {{0, 2}},
        .sprint = {
            {0, 64},
            {38'189'056, 16},
        },
        .jaipur_block = 23'850'000,
    },
};

const ChainConfig kMumbaiConfig{
    .chain_id = 80001,
    .homestead_block = 0,
    .tangerine_whistle_block = 0,
    .spurious_dragon_block = 0,
    .byzantium_block = 0,
    .constantinople_block = 0,
    .petersburg_block = 0,
    .istanbul_block = 2'722'000,
    .muir_glacier_block = 2'722'000,
    .berlin_block = 13'996'000,
    .london_block = 22'640'000,
    .burnt_contract = {
        {22'640'000, 0x70bca57f4579f58670ab2d18ef16e02c17553c38_address},
        {41'874'000, 0x617b94CCCC2511808A3C9478ebb96f455CF167aA_address},
    },
    .rule_set_config = protocol::BorConfig{
        .period = {
            {0, 2},
            {25'275'000, 5},
            {29'638'656, 2},
        },
        .sprint = {
            {0, 64},
            {29'638'656, 16},
        },
        .jaipur_block = 22'770'000,
        .agra_block = 41'874'000,
    },
};

}  // namespace silkworm
