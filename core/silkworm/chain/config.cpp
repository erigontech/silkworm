/*
   Copyright 2021 The Silkworm Authors

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

#include <functional>

#include <silkworm/common/as_range.hpp>

namespace silkworm {

static const std::vector<std::pair<std::string, const ChainConfig*>> kKnownChainConfigs{
    {"mainnet", &kMainnetConfig},  //
    {"ropsten", &kRopstenConfig},  //
    {"rinkeby", &kRinkebyConfig},  //
    {"goerli", &kGoerliConfig}     //
};

constexpr const char* kTerminalTotalDifficulty{"terminalTotalDifficulty"};
constexpr const char* kTerminalBlockNumber{"terminalBlockNumber"};
constexpr const char* kTerminalBlockHash{"terminalBlockHash"};

static inline void member_to_json(nlohmann::json& json, const std::string& key, const std::optional<uint64_t>& source) {
    if (source.has_value()) {
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
    switch (seal_engine) {
        case silkworm::SealEngineType::kEthash:
            ret.emplace("ethash", empty_object);
            break;
        case silkworm::SealEngineType::kClique:
            ret.emplace("clique", empty_object);
            break;
        case silkworm::SealEngineType::kAuRA:
            ret.emplace("aura", empty_object);
            break;
        default:
            break;
    }

    for (size_t i{0}; i < EVMC_MAX_REVISION; ++i) {
        member_to_json(ret, kJsonForkNames[i], fork_blocks[i]);
    }

    member_to_json(ret, "daoForkBlock", dao_block);
    member_to_json(ret, "muirGlacierBlock", muir_glacier_block);
    member_to_json(ret, "arrowGlacierBlock", arrow_glacier_block);
    member_to_json(ret, kTerminalBlockNumber, terminal_block_number);

    if (terminal_total_difficulty.has_value()) {
        // TODO (Andrew) geth probably treats terminalTotalDifficulty as a JSON number
        ret[kTerminalTotalDifficulty] = to_string(*terminal_total_difficulty);
    }

    if (terminal_block_hash.has_value()) {
        ret[kTerminalBlockHash] = "0x" + to_hex(*terminal_block_hash);
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
        config.seal_engine = SealEngineType::kEthash;
    } else if (json.contains("clique")) {
        config.seal_engine = SealEngineType::kClique;
    } else if (json.contains("aura")) {
        config.seal_engine = SealEngineType::kAuRA;
    } else {
        config.seal_engine = SealEngineType::kNoProof;
    }

    for (size_t i{0}; i < EVMC_MAX_REVISION; ++i) {
        read_json_config_member(json, kJsonForkNames[i], config.fork_blocks[i]);
    }

    read_json_config_member(json, "daoForkBlock", config.dao_block);
    read_json_config_member(json, "muirGlacierBlock", config.muir_glacier_block);
    read_json_config_member(json, "arrowGlacierBlock", config.arrow_glacier_block);
    read_json_config_member(json, kTerminalBlockNumber, config.terminal_block_number);
    if (json.contains(kTerminalTotalDifficulty)) {
        config.terminal_total_difficulty =
            intx::from_string<intx::uint256>(json[kTerminalTotalDifficulty].get<std::string>());
    }

    if (json.contains(kTerminalBlockHash)) {
        auto terminal_block_hash_bytes{from_hex(json[kTerminalBlockHash].get<std::string>())};
        if (terminal_block_hash_bytes.has_value()) {
            config.terminal_block_hash = to_bytes32(*terminal_block_hash_bytes);
        }
    }
    return config;
}

std::optional<uint64_t> ChainConfig::revision_block(evmc_revision rev) const noexcept {
    if (rev == EVMC_FRONTIER) {
        return 0;
    }
    size_t i{static_cast<size_t>(rev) - 1};
    return fork_blocks.at(i);
}

void ChainConfig::set_revision_block(evmc_revision rev, std::optional<uint64_t> block) {
    if (rev > 0) {  // Frontier block is always 0
        fork_blocks[static_cast<size_t>(rev) - 1] = block;
    }
}

bool operator==(const ChainConfig& a, const ChainConfig& b) { return a.to_json() == b.to_json(); }

std::ostream& operator<<(std::ostream& out, const ChainConfig& obj) { return out << obj.to_json(); }

const ChainConfig* lookup_chain_config(std::variant<uint64_t, std::string> identifier) noexcept {
    auto it{as_range::find_if(kKnownChainConfigs,
                              [&identifier](const std::pair<std::string, const ChainConfig*>& x) -> bool {
                                  if (std::holds_alternative<std::string>(identifier)) {
                                      return iequals(x.first, std::get<std::string>(identifier));
                                  }
                                  return x.second->chain_id == std::get<uint64_t>(identifier);
                              })};
    if (it == kKnownChainConfigs.end()) {
        return nullptr;
    }
    return it->second;
}

std::map<std::string, uint64_t> get_known_chains_map() noexcept {
    std::map<std::string, uint64_t> ret;
    as_range::for_each(kKnownChainConfigs, [&ret](const std::pair<std::string, const ChainConfig*>& x) -> void {
        ret[x.first] = x.second->chain_id;
    });
    return ret;
}

}  // namespace silkworm
