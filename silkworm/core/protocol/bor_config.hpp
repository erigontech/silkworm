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
    ConfigMap<uint64_t> period;
    ConfigMap<uint64_t> sprint;

    BlockNum jaipur_block{0};

    // https://forum.polygon.technology/t/pip-28-agra-hardfork
    std::optional<BlockNum> agra_block{std::nullopt};

    [[nodiscard]] uint64_t sprint_size(BlockNum number) const noexcept;

    [[nodiscard]] nlohmann::json to_json() const noexcept;

    [[nodiscard]] static std::optional<BorConfig> from_json(const nlohmann::json& json) noexcept;

    bool operator==(const BorConfig&) const = default;
};

}  // namespace silkworm::protocol
