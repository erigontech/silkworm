// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/snapshots/index_builders_factory.hpp>
#include <silkworm/db/datastore/snapshots/schema.hpp>

namespace silkworm::db::blocks {

class BlocksIndexBuildersFactory : public snapshots::IndexBuildersFactory {
  public:
    explicit BlocksIndexBuildersFactory(snapshots::Schema::RepositoryDef schema)
        : schema_{std::move(schema)} {}
    ~BlocksIndexBuildersFactory() override = default;

    std::vector<std::shared_ptr<snapshots::IndexBuilder>> index_builders(const snapshots::SnapshotPath& segment_path) const override;
    snapshots::SnapshotPathList index_dependency_paths(const snapshots::SnapshotPath& index_path) const override;

  private:
    snapshots::Schema::RepositoryDef schema_;
};

}  // namespace silkworm::db::blocks
