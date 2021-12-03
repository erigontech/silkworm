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

#include <silkworm/db/access_layer.hpp>

namespace silkworm::db::table {

void check_or_create_chaindata_tables(mdbx::txn& txn) {
    for (const auto& config : kChainDataTables) {
        if (db::has_map(txn, config.name)) {
            auto table_map{txn.open_map(config.name)};
            auto table_info{txn.get_handle_info(table_map)};
            auto table_key_mode{table_info.key_mode()};
            auto table_value_mode{table_info.value_mode()};
            if (table_key_mode != config.key_mode || table_value_mode != config.value_mode) {
                throw std::runtime_error("MDBX Table schema incompatible: " + std::string(config.name) +
                                         " has incompatible flags.");
            }
            continue;
        }
        // Create missing table
        (void)txn.create_map(config.name, config.key_mode, config.value_mode);  // Will throw if tx is RO
    }

    auto db_schema_version{db::read_schema_version(txn)};
    if (!db_schema_version.has_value()) {
        db::write_schema_version(txn, kRequiredSchemaVersion);
    } else if (db_schema_version.value() != kRequiredSchemaVersion) {
        throw std::runtime_error("Incompatible schema version. Expected " + kRequiredSchemaVersion.to_string() +
                                 " got " + db_schema_version.value().to_string());
    }
}

}  // namespace silkworm::db::table
