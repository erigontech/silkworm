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

#include <silkworm/core/common/as_range.hpp>
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
    switch (protocol_rule_set) {
        case protocol::RuleSetType::kEthash:
            ret.emplace("ethash", empty_object);
            break;
        case protocol::RuleSetType::kClique:
            ret.emplace("clique", empty_object);
            break;
        case protocol::RuleSetType::kBor:
            ret.emplace("bor", empty_object);
            break;
        default:
            break;
    }

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
    member_to_json(ret, "arrowGlacierBlock", arrow_glacier_block);
    member_to_json(ret, "grayGlacierBlock", gray_glacier_block);

    if (terminal_total_difficulty) {
        // TODO(yperbasis) geth probably treats terminalTotalDifficulty as a JSON number
        ret[kTerminalTotalDifficulty] = to_string(*terminal_total_difficulty);
    }

    member_to_json(ret, "mergeNetsplitBlock", merge_netsplit_block);
    member_to_json(ret, "shanghaiTime", shanghai_time);
    member_to_json(ret, "cancunTime", cancun_time);

    if (eip1559_fee_collector) {
        ret["eip1559FeeCollector"] = address_to_hex(*eip1559_fee_collector);
    }

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
        config.protocol_rule_set = protocol::RuleSetType::kEthash;
    } else if (json.contains("clique")) {
        config.protocol_rule_set = protocol::RuleSetType::kClique;
    } else if (json.contains("bor")) {
        config.protocol_rule_set = protocol::RuleSetType::kBor;
    } else {
        config.protocol_rule_set = protocol::RuleSetType::kNoProof;
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

    if (json.contains("eip1559FeeCollector")) {
        const auto eip1559_fee_collector{json["eip1559FeeCollector"].get<std::string>()};
        config.eip1559_fee_collector = hex_to_address(eip1559_fee_collector);
    }

    /* Note ! genesis_hash is purposely omitted. It must be loaded from db after the
     * effective genesis block has been persisted */

    return config;
}

evmc_revision ChainConfig::revision(uint64_t block_number, uint64_t block_time) const noexcept {
    if (cancun_time && block_time >= cancun_time) return EVMC_CANCUN;
    if (shanghai_time && block_time >= shanghai_time) return EVMC_SHANGHAI;

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

std::map<std::string, uint64_t> get_known_chains_map() noexcept {
    std::map<std::string, uint64_t> ret;
    as_range::for_each(kKnownChainConfigs, [&ret](const std::pair<std::string, const ChainConfig*>& x) -> void {
        ret[x.first] = x.second->chain_id;
    });
    return ret;
}

}  // namespace silkworm
