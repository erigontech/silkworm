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

#include "state_bundle_factory.hpp"

namespace silkworm::db::state {

using namespace snapshots;

SnapshotBundle StateBundleFactory::make(const std::filesystem::path& dir_path, snapshots::StepRange range) const {
    return SnapshotBundle{
        range,
        make_bundle_data(schema_, dir_path, range),
    };
}

SnapshotBundlePaths StateBundleFactory::make_paths(const std::filesystem::path& dir_path, snapshots::StepRange range) const {
    return SnapshotBundlePaths{
        schema_,
        dir_path,
        range,
    };
}

std::vector<std::shared_ptr<IndexBuilder>> StateBundleFactory::index_builders(const SnapshotPath& segment_path) const {
    return {};
}

std::vector<std::shared_ptr<IndexBuilder>> StateBundleFactory::index_builders(const SnapshotPathList& segment_paths) const {
    std::vector<std::shared_ptr<IndexBuilder>> all_builders;
    for (const auto& path : segment_paths) {
        auto builders = index_builders(path);
        all_builders.insert(all_builders.end(), builders.begin(), builders.end());
    }
    return all_builders;
}

SnapshotPathList StateBundleFactory::index_dependency_paths(const SnapshotPath& index_path) const {
    return {};
}

}  // namespace silkworm::db::state
