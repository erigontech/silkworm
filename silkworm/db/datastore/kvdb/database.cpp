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

#include "database.hpp"

namespace silkworm::datastore::kvdb {

static MapConfig make_table_config(const Schema::TableDef& table) {
    return MapConfig{
        table.name().c_str(),
        mdbx::key_mode::usual,
        table.is_multi_value() ? mdbx::value_mode::multi : mdbx::value_mode::single,
    };
}

static EntityMap<MapConfig> make_table_configs(
    const Schema::EntityDef& entity) {
    EntityMap<MapConfig> results;
    for (auto& [name, def] : entity.tables()) {
        results.emplace(name, make_table_config(def));
    }
    return results;
}

DatabaseRef::EntitiesMap make_entities(
    const Schema::DatabaseDef& schema) {
    DatabaseRef::EntitiesMap results;
    for (auto& [name, def] : schema.entities()) {
        results.emplace(name, make_table_configs(*def));
    }
    return results;
}

void Database::create_tables() {
    RWTxnManaged tx = access_rw().start_rw_tx();
    for (auto& entity : entities_) {
        for (auto& entry : entity.second) {
            MapConfig& map_config = entry.second;
            tx->create_map(map_config.name, map_config.key_mode, map_config.value_mode);
        }
    }
    tx.commit_and_stop();
}

Domain DatabaseRef::domain(datastore::EntityName name) const {
    auto& entity = entities_.at(name);
    auto& domain_def = dynamic_cast<Schema::DomainDef&>(*schema_.entities().at(name));
    Domain domain{
        entity.at(Schema::kDomainValuesName),
        domain_def.has_large_values(),
        std::nullopt,
    };
    if (entity.contains(Schema::kHistoryValuesName)) {
        domain.history.emplace(History{
            entity.at(Schema::kHistoryValuesName),
            domain_def.has_large_values(),
            inverted_index(name),
        });
    }
    return domain;
}

InvertedIndex DatabaseRef::inverted_index(datastore::EntityName name) const {
    auto& entity = entities_.at(name);
    return InvertedIndex{
        entity.at(Schema::kInvIdxKeysName),
        entity.at(Schema::kInvIdxIndexName),
    };
}

}  // namespace silkworm::datastore::kvdb
