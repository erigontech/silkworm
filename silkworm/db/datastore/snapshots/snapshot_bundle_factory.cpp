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

#include "snapshot_bundle_factory.hpp"

namespace silkworm::snapshots {

std::vector<std::shared_ptr<IndexBuilder>> SnapshotBundleFactory::index_builders(const SnapshotPathList& segment_paths) const {
    std::vector<std::shared_ptr<IndexBuilder>> all_builders;
    for (const auto& path : segment_paths) {
        auto builders = index_builders(path);
        all_builders.insert(all_builders.end(), builders.begin(), builders.end());
    }
    return all_builders;
}

}  // namespace silkworm::snapshots
