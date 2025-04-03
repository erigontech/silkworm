// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
