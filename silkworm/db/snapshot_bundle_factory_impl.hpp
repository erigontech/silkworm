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

#include <silkworm/db/datastore/snapshots/snapshot_bundle_factory.hpp>

namespace silkworm::db {

struct SnapshotBundleFactoryImpl : public snapshots::SnapshotBundleFactory {
    ~SnapshotBundleFactoryImpl() override = default;

    snapshots::SnapshotBundle make(PathByTypeProvider snapshot_path, PathByTypeProvider index_path) const override;
    snapshots::SnapshotBundle make(const std::filesystem::path& dir_path, snapshots::StepRange range) const override;
    std::vector<std::shared_ptr<snapshots::IndexBuilder>> index_builders(const snapshots::SnapshotPath& segment_path) const override;
    std::vector<std::shared_ptr<snapshots::IndexBuilder>> index_builders(const snapshots::SnapshotPathList& segment_paths) const override;
};

}  // namespace silkworm::db
