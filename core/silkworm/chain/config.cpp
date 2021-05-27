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

namespace silkworm {

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

    for (int i{0}; i < EVMC_MAX_REVISION; ++i) {
        member_to_json(ret, kJsonForkNames[i], fork_blocks[i]);
    }

    member_to_json(ret, "muirGlacierBlock", muir_glacier_block);
    member_to_json(ret, "daoForkBlock", dao_block);

    return ret;
}

std::optional<ChainConfig> ChainConfig::from_json(const nlohmann::json& json) noexcept {
    if (json == nlohmann::json::value_t::discarded || !json.contains("chainId") || !json["chainId"].is_number()) {
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
    }

    for (int i{0}; i < EVMC_MAX_REVISION; ++i) {
        read_json_config_member(json, kJsonForkNames[i], config.fork_blocks[i]);
    }

    read_json_config_member(json, "muirGlacierBlock", config.muir_glacier_block);
    read_json_config_member(json, "daoForkBlock", config.dao_block);

    return config;
}

evmc_revision ChainConfig::revision(uint64_t block_number) const noexcept {
    for (int i{EVMC_MAX_REVISION - 1}; i >= 0; --i) {
        if (fork_blocks[i].has_value() && block_number >= fork_blocks[i].value()) {
            return static_cast<evmc_revision>(i + 1);
        }
    }
    return EVMC_FRONTIER;
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
        fork_blocks[rev - 1] = block;
    }
}

bool operator==(const ChainConfig& a, const ChainConfig& b) { return a.to_json() == b.to_json(); }

std::ostream& operator<<(std::ostream& out, const ChainConfig& obj) { return out << obj.to_json(); }

}  // namespace silkworm
