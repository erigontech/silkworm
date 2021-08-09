/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "tables.hpp"

namespace silkworm::db::table {

void create_all(mdbx::txn& txn) {
    for (const auto& config : kTables) {
        (void)txn.create_map(config.name, config.key_mode, config.value_mode);  // Will throw if tx is RO
    }
}

std::optional<db::MapConfig> get_config(std::string name) {
    for (auto config : kTables) {
        if (strcmp(config.name, name.c_str()) == 0) {
            return {config};
        }
    }
    return std::nullopt;
}

}  // namespace silkworm::db::table
