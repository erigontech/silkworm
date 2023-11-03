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

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/small_map.hpp>

namespace silkworm::protocol {

struct BorConfig {
    SmallMap<BlockNum, uint64_t> period;
    SmallMap<BlockNum, uint64_t> sprint;

    BlockNum jaipur_block{0};

    // https://forum.polygon.technology/t/pip-28-agra-hardfork
    std::optional<BlockNum> agra_block{std::nullopt};

    [[nodiscard]] uint64_t sprint_size(BlockNum number) const noexcept;

    [[nodiscard]] nlohmann::json to_json() const noexcept;

    [[nodiscard]] static std::optional<BorConfig> from_json(const nlohmann::json& json) noexcept;

    bool operator==(const BorConfig&) const = default;
};

// Looks up a config value as of a given block number.
// The assumption here is that config is a càdlàg map of starting_from_block -> value.
// For example, config of {{0, "a"}, {10, "b"}, {20, "c"}}
// means that the config value is "a" for blocks 0–9,
// "b" for blocks 10–19, and "c" for block 20 and above.
//
// N.B. Similar to borKeyValueConfigHelper in Erigon.
template <typename T>
[[nodiscard]] constexpr const T* bor_config_value_lookup(const SmallMap<BlockNum, T>& config, BlockNum number) noexcept {
    auto it{config.begin()};
    if (config.empty() || it->first > number) {
        return nullptr;
    }
    for (; (it + 1) != config.end(); ++it) {
        if (it->first <= number && number < (it + 1)->first) {
            return &(it->second);
        }
    }
    return &(it->second);
}

}  // namespace silkworm::protocol
