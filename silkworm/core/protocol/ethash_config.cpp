/*
   Copyright 2024 The Silkworm Authors

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

#include "ethash_config.hpp"

namespace silkworm::protocol {

nlohmann::json EthashConfig::to_json() const noexcept {
    nlohmann::json ret(nlohmann::json::value_t::object);
    if (!validate_seal) {
        ret.emplace("validateSeal", validate_seal);
    }
    return ret;
}

std::optional<EthashConfig> EthashConfig::from_json(const nlohmann::json& json) noexcept {
    if (json.is_discarded() || !json.is_object()) {
        return std::nullopt;
    }

    EthashConfig config;
    if (json.contains("validateSeal")) {
        config.validate_seal = json["validateSeal"].get<bool>();
    }
    return config;
}

}  // namespace silkworm::protocol
