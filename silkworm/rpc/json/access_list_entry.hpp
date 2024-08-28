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

#include <nlohmann/json.hpp>

#include <silkworm/core/types/transaction.hpp>
#include <silkworm/rpc/json/glaze.hpp>

namespace silkworm::rpc {
struct GlazeJsonAccessList {
    char address[kAddressHexSize]{};
    std::vector<std::string> storage_keys;
    struct glaze {
        using T = GlazeJsonAccessList;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "address", &T::address,
            "storageKeys", &T::storage_keys);
    };
};

}  // namespace silkworm::rpc

namespace silkworm {

void from_json(const nlohmann::json& json, AccessListEntry& entry);
void to_json(nlohmann::json& json, const AccessListEntry& access_list);

}  // namespace silkworm
