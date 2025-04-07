// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "index_builders_factory.hpp"

namespace silkworm::snapshots {

std::vector<std::shared_ptr<IndexBuilder>> IndexBuildersFactory::index_builders(const SnapshotPathList& segment_paths) const {
    std::vector<std::shared_ptr<IndexBuilder>> all_builders;
    for (const auto& path : segment_paths) {
        auto builders = index_builders(path);
        all_builders.insert(all_builders.end(), builders.begin(), builders.end());
    }
    return all_builders;
}

}  // namespace silkworm::snapshots
