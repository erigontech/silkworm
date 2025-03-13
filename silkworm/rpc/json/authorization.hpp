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

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/core/types/transaction.hpp>
#include <silkworm/rpc/json/glaze.hpp>

namespace silkworm::rpc {

struct GlazeJsonAuthorization {
    char chain_id[kInt256HexSize]{};
    char address[kAddressHexSize]{};
    char y_parity[sizeof(uint8_t)]{};
    char r[kInt256HexSize]{};
    char s[kInt256HexSize]{};
    std::vector<std::string> storage_keys;
    struct glaze {
        using T = GlazeJsonAuthorization;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "chainId", &T::chain_id,
            "address", &T::address,
            "yParity", &T::y_parity,
            "r", &T::r,
            "s", &T::s);
    };
};

}  // namespace silkworm::rpc

namespace silkworm {

void from_json(const nlohmann::json& json, Authorization& entry);
void to_json(nlohmann::json& json, const Authorization& authorization);

}  // namespace silkworm
