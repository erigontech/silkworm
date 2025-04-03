// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

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
        EntityMap<std::unique_ptr<kvdb::Database>> databases,
        EntityMap<std::unique_ptr<snapshots::SnapshotRepository>> repositories)
        : schema_{std::move(schema)},
          databases_{std::move(databases)},
          repositories_{std::move(repositories)} {}

    const Schema& schema() const { return schema_; }

    kvdb::Database& default_database() const { return database(kvdb::Schema::kDefaultEntityName); }
    kvdb::Database& database(const EntityName& name) const { return *databases_.at(name); }
    snapshots::SnapshotRepository& repository(const EntityName& name) const { return *repositories_.at(name); }

  private:
    Schema schema_;
    EntityMap<std::unique_ptr<kvdb::Database>> databases_;
    EntityMap<std::unique_ptr<snapshots::SnapshotRepository>> repositories_;
};

}  // namespace silkworm::datastore
