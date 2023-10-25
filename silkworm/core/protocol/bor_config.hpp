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

#pragma once

#include <optional>

#include <nlohmann/json.hpp>

#include <silkworm/core/chain/config_map.hpp>
#include <silkworm/core/common/base.hpp>

namespace silkworm::protocol {

struct BorConfig {
    ConfigMap<uint64_t> sprint;  // from block -> sprint size

    BlockNum jaipur_block{0};

    [[nodiscard]] uint64_t sprint_size(BlockNum number) const noexcept;

    [[nodiscard]] nlohmann::json to_json() const noexcept;

    [[nodiscard]] static std::optional<BorConfig> from_json(const nlohmann::json& json) noexcept;

    bool operator==(const BorConfig&) const = default;
};

// Lookups a config value as of a given block number.
// config is a càdlàg map of starting_from_block -> value.
// Similar to borKeyValueConfigHelper in Erigon.
template <typename T>
std::optional<T> bor_config_lookup(const std::vector<std::pair<BlockNum, T>>& config, BlockNum number) noexcept {
    // TODO(yperbasis): replace with constexpr map sorted by block number
    if (config.empty() || config.front().first > number) {
        return std::nullopt;
    }

    for (size_t i{0}; i < config.size() - 1; ++i) {
        if (config[i].first <= number && number < config[i + 1].first) {
            return config[i].second;
        }
    }

    return config.back().second;
}

}  // namespace silkworm::protocol
