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

#include <silkworm/db/datastore/snapshots/schema.hpp>
#include <silkworm/db/datastore/snapshots/snapshot_bundle_factory.hpp>

namespace silkworm::db::state {

class StateBundleFactory : public snapshots::SnapshotBundleFactory {
  public:
    StateBundleFactory() {}
    StateBundleFactory(snapshots::Schema::RepositoryDef schema)
        : schema_{std::move(schema)} {}
    ~StateBundleFactory() override = default;

    std::vector<std::shared_ptr<snapshots::IndexBuilder>> index_builders(const snapshots::SnapshotPath& segment_path) const override;
    std::vector<std::shared_ptr<snapshots::IndexBuilder>> index_builders(const snapshots::SnapshotPathList& segment_paths) const override;
    snapshots::SnapshotPathList index_dependency_paths(const snapshots::SnapshotPath& index_path) const override;

  private:
    snapshots::Schema::RepositoryDef schema_;
};

}  // namespace silkworm::db::state
