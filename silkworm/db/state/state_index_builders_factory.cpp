// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "state_index_builders_factory.hpp"

namespace silkworm::db::state {

using namespace snapshots;

std::vector<std::shared_ptr<IndexBuilder>> StateIndexBuildersFactory::index_builders(const SnapshotPath& /*segment_path*/) const {
    return {};
}

SnapshotPathList StateIndexBuildersFactory::index_dependency_paths(const SnapshotPath& /*index_path*/) const {
    return {};
}

}  // namespace silkworm::db::state
