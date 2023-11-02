/*
   Copyright 2023 The Silkworm Authors

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

#include "bor_config.hpp"

#include <string>

#include <silkworm/core/common/assert.hpp>

namespace silkworm::protocol {

uint64_t BorConfig::sprint_size(BlockNum number) const noexcept {
    const uint64_t* size{sprint.value(number)};
    SILKWORM_ASSERT(size);
    return *size;
}

nlohmann::json BorConfig::to_json() const noexcept {
    nlohmann::json ret;
    nlohmann::json period_json = nlohmann::json::object();
    for (const auto& [from, val] : period) {
        period_json[std::to_string(from)] = val;
    }
    ret["period"] = period_json;
    nlohmann::json sprint_json = nlohmann::json::object();
    for (const auto& [from, val] : sprint) {
        sprint_json[std::to_string(from)] = val;
    }
    ret["sprint"] = sprint_json;
    ret["jaipurBlock"] = jaipur_block;
    if (agra_block) {
        ret["agraBlock"] = *agra_block;
    }
    return ret;
}

std::optional<BorConfig> BorConfig::from_json(const nlohmann::json& json) noexcept {
    if (json.is_discarded() || !json.is_object()) {
        return std::nullopt;
    }

    BorConfig config;

    std::vector<std::pair<BlockNum, uint64_t>> period;
    for (const auto& item : json["period"].items()) {
        const BlockNum from{std::stoull(item.key(), nullptr, 0)};
        period.emplace_back(from, item.value().get<uint64_t>());
    }
    config.period = ConfigMap<uint64_t>(period.begin(), period.end());

    std::vector<std::pair<BlockNum, uint64_t>> sprint;
    for (const auto& item : json["sprint"].items()) {
        const BlockNum from{std::stoull(item.key(), nullptr, 0)};
        sprint.emplace_back(from, item.value().get<uint64_t>());
    }
    config.sprint = ConfigMap<uint64_t>(sprint.begin(), sprint.end());

    config.jaipur_block = json["jaipurBlock"].get<BlockNum>();
    if (json.contains("agraBlock")) {
        config.agra_block = json["agraBlock"].get<BlockNum>();
    }
    return config;
}

}  // namespace silkworm::protocol
