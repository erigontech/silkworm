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
