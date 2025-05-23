// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <utility>

#include "domain.hpp"
#include "inverted_index.hpp"
#include "mdbx.hpp"
#include "schema.hpp"

namespace silkworm::datastore::kvdb {

class Database;
class DatabaseUnmanaged;

class DatabaseRef {
  public:
    using EntitiesMap = EntityMap<EntityMap<MapConfig>>;

    ROAccess access_ro() const { return ROAccess{env_}; }
    RWAccess access_rw() const { return RWAccess{env_}; }

    Domain domain(datastore::EntityName name) const;
    InvertedIndex inverted_index(datastore::EntityName name) const;

  private:
    // this is private, use Database.ref() or DatabaseUnmanaged.ref() to create
    DatabaseRef(
        mdbx::env env,
        const Schema::DatabaseDef& schema,
        const EntitiesMap& entities)
        : env_{std::move(env)},
          schema_{schema},
          entities_{entities} {}

    friend class Database;
    friend class DatabaseUnmanaged;

    mdbx::env env_;
    const Schema::DatabaseDef& schema_;
    const EntitiesMap& entities_;
};

DatabaseRef::EntitiesMap make_entities(const Schema::DatabaseDef& schema);

class Database {
  public:
    Database(
        mdbx::env_managed env,
        Schema::DatabaseDef schema)
        : env_{std::move(env)},
          schema_{std::move(schema)},
          entities_{make_entities(schema_)} {}

    ROAccess access_ro() const { return ref().access_ro(); }
    RWAccess access_rw() const { return ref().access_rw(); }

    Domain domain(datastore::EntityName name) const { return ref().domain(name); }
    InvertedIndex inverted_index(datastore::EntityName name) const { return ref().inverted_index(name); }

    DatabaseRef ref() const { return {env_, schema_, entities_}; }  // NOLINT(cppcoreguidelines-slicing)

    void create_tables();

  private:
    mdbx::env_managed env_;
    Schema::DatabaseDef schema_;
    EntityMap<EntityMap<MapConfig>> entities_;
};

class DatabaseUnmanaged {
  public:
    DatabaseUnmanaged(
        EnvUnmanaged env,
        Schema::DatabaseDef schema)
        : env_{std::move(env)},
          schema_{std::move(schema)},
          entities_{make_entities(schema_)} {}

    ROAccess access_ro() const { return ref().access_ro(); }
    RWAccess access_rw() const { return ref().access_rw(); }

    Domain domain(datastore::EntityName name) const { return ref().domain(name); }
    InvertedIndex inverted_index(datastore::EntityName name) const { return ref().inverted_index(name); }

    DatabaseRef ref() const { return {env_, schema_, entities_}; }  // NOLINT(cppcoreguidelines-slicing)

  private:
    EnvUnmanaged env_;
    Schema::DatabaseDef schema_;
    EntityMap<EntityMap<MapConfig>> entities_;
};

}  // namespace silkworm::datastore::kvdb
