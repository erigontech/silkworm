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

#include "access_list_entry.hpp"

#include <silkworm/core/common/util.hpp>

#include "types.hpp"

namespace silkworm {

void from_json(const nlohmann::json& json, AccessListEntry& entry) {
    entry.account = json.at("address").get<evmc::address>();
    entry.storage_keys = json.at("storageKeys").get<std::vector<evmc::bytes32>>();
}

void to_json(nlohmann::json& json, const AccessListEntry& access_list) {
    json["address"] = access_list.account;
    json["storageKeys"] = access_list.storage_keys;
}

}  // namespace silkworm
