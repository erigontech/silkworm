// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/snapshots/index_builders_factory.hpp>
#include <silkworm/db/datastore/snapshots/schema.hpp>

namespace silkworm::db::state {

class StateIndexBuildersFactory : public snapshots::IndexBuildersFactory {
  public:
    StateIndexBuildersFactory() = default;
    explicit StateIndexBuildersFactory(snapshots::Schema::RepositoryDef schema)
        : schema_{std::move(schema)} {}
    ~StateIndexBuildersFactory() override = default;

    std::vector<std::shared_ptr<snapshots::IndexBuilder>> index_builders(const snapshots::SnapshotPath& segment_path) const override;
    snapshots::SnapshotPathList index_dependency_paths(const snapshots::SnapshotPath& index_path) const override;

  private:
    snapshots::Schema::RepositoryDef schema_;
};

}  // namespace silkworm::db::state
