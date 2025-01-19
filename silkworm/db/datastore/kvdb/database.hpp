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

#include <map>
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
    using EntitiesMap = std::map<datastore::EntityName, std::map<datastore::EntityName, MapConfig>>;

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

class DatabaseBase {
  public:
    virtual ~DatabaseBase() = default;

    ROAccess access_ro() const { return ref().access_ro(); }
    RWAccess access_rw() const { return ref().access_rw(); }

    Domain domain(datastore::EntityName name) const { return ref().domain(name); }
    InvertedIndex inverted_index(datastore::EntityName name) { return ref().inverted_index(name); }

    virtual DatabaseRef ref() const = 0;
};

class Database : public DatabaseBase {
  public:
    Database(
        mdbx::env_managed env,
        Schema::DatabaseDef schema)
        : env_{std::move(env)},
          schema_{std::move(schema)},
          entities_{make_entities(schema_)} {}

    DatabaseRef ref() const override { return {env_, schema_, entities_}; }  // NOLINT(cppcoreguidelines-slicing)

    void create_tables();

  private:
    mdbx::env_managed env_;
    Schema::DatabaseDef schema_;
    std::map<datastore::EntityName, std::map<datastore::EntityName, MapConfig>> entities_;
};

class DatabaseUnmanaged : public DatabaseBase {
  public:
    DatabaseUnmanaged(
        EnvUnmanaged env,
        Schema::DatabaseDef schema)
        : env_{std::move(env)},
          schema_{std::move(schema)},
          entities_{make_entities(schema_)} {}

    DatabaseRef ref() const override { return {env_, schema_, entities_}; }  // NOLINT(cppcoreguidelines-slicing)

  private:
    EnvUnmanaged env_;
    Schema::DatabaseDef schema_;
    std::map<datastore::EntityName, std::map<datastore::EntityName, MapConfig>> entities_;
};

}  // namespace silkworm::datastore::kvdb
