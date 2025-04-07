// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <vector>

#include "common/snapshot_path.hpp"
#include "index_builder.hpp"

namespace silkworm::snapshots {

struct IndexBuildersFactory {
    virtual ~IndexBuildersFactory() = default;

    virtual std::vector<std::shared_ptr<IndexBuilder>> index_builders(const SnapshotPath& segment_path) const = 0;
    std::vector<std::shared_ptr<IndexBuilder>> index_builders(const SnapshotPathList& segment_paths) const;

    virtual SnapshotPathList index_dependency_paths(const SnapshotPath& index_path) const = 0;
};

}  // namespace silkworm::snapshots
