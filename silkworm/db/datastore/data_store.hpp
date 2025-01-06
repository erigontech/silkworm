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
#include <memory>

#include "common/entity_name.hpp"
#include "kvdb/database.hpp"
#include "schema.hpp"
#include "snapshots/snapshot_repository.hpp"

namespace silkworm::datastore {

class DataStore {
  public:
    DataStore(
        Schema schema,
        std::map<EntityName, std::unique_ptr<kvdb::Database>> databases,
        std::map<EntityName, std::unique_ptr<snapshots::SnapshotRepository>> repositories)
        : schema_{std::move(schema)},
          databases_{std::move(databases)},
          repositories_{std::move(repositories)} {}

    const Schema& schema() const { return schema_; }

    kvdb::Database& default_database() const { return database(kvdb::Schema::kDefaultEntityName); }
    kvdb::Database& database(const EntityName& name) const { return *databases_.at(name); }
    snapshots::SnapshotRepository& repository(const EntityName& name) const { return *repositories_.at(name); }

  private:
    Schema schema_;
    std::map<EntityName, std::unique_ptr<kvdb::Database>> databases_;
    std::map<EntityName, std::unique_ptr<snapshots::SnapshotRepository>> repositories_;
};

}  // namespace silkworm::datastore
