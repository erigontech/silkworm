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

#include "schema.hpp"

namespace silkworm::datastore::kvdb {

static std::string make_table_name(datastore::EntityName base_name, std::string_view suffix) {
    return base_name.to_string() + std::string{suffix};
}

Schema::DomainDef Schema::DatabaseDef::make_domain_schema(datastore::EntityName name) {
    Schema::DomainDef schema;
    schema.table(kDomainValuesName)
        .name(make_table_name(name, "Vals"))
        .enable_multi_value();
    define_history_schema(name, schema);
    return schema;
}

Schema::EntityDef Schema::DatabaseDef::make_history_schema(datastore::EntityName name) {
    Schema::EntityDef schema;
    define_history_schema(name, schema);
    return schema;
}

void Schema::DatabaseDef::define_history_schema(datastore::EntityName name, EntityDef& schema) {
    schema.table(kHistoryValuesName)
        .name(make_table_name(name, "HistoryVals"))
        .enable_multi_value();
    define_inverted_index_schema(name, schema);
    // update the inverted index table name to have a "HistoryKeys" suffix
    schema.table(kInvIdxKeysName)
        .name(make_table_name(name, "HistoryKeys"));
}

void Schema::DatabaseDef::undefine_history_schema(EntityDef& schema) {
    schema.undefine(kHistoryValuesName);
    undefine_inverted_index_schema(schema);
}

Schema::EntityDef Schema::DatabaseDef::make_inverted_index_schema(datastore::EntityName name) {
    Schema::EntityDef schema;
    define_inverted_index_schema(name, schema);
    return schema;
}

void Schema::DatabaseDef::define_inverted_index_schema(datastore::EntityName name, EntityDef& schema) {
    schema.table(kInvIdxKeysName)
        .name(make_table_name(name, "Keys"))
        .enable_multi_value();
    schema.table(kInvIdxIndexName)
        .name(make_table_name(name, "Idx"))
        .enable_multi_value();
}

void Schema::DatabaseDef::undefine_inverted_index_schema(EntityDef& schema) {
    schema.undefine(kInvIdxKeysName);
    schema.undefine(kInvIdxIndexName);
}

}  // namespace silkworm::datastore::kvdb
