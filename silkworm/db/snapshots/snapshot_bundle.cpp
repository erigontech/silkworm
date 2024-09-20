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

#include "snapshot_bundle.hpp"

#include <silkworm/infra/common/ensure.hpp>

namespace silkworm::snapshots {

SnapshotBundle::~SnapshotBundle() {
    close();
}

void SnapshotBundle::reopen() {
    for (auto& snapshot_ref : snapshots()) {
        snapshot_ref.get().reopen_segment();
        ensure(!snapshot_ref.get().empty(), [&]() {
            return "invalid empty snapshot " + snapshot_ref.get().fs_path().string();
        });
    }
    for (auto& index_ref : indexes()) {
        index_ref.get().reopen_index();
    }
}

void SnapshotBundle::close() {
    for (auto& index_ref : indexes()) {
        index_ref.get().close_index();
    }
    for (auto& snapshot_ref : snapshots()) {
        snapshot_ref.get().close();
    }
    if (on_close_callback_) {
        on_close_callback_(*this);
    }
}

std::vector<std::filesystem::path> SnapshotBundle::files() {
    std::vector<std::filesystem::path> files;
    files.reserve(kSnapshotsCount + kIndexesCount);

    for (auto& snapshot_ref : snapshots()) {
        files.push_back(snapshot_ref.get().path().path());
    }
    for (auto& index_ref : indexes()) {
        files.push_back(index_ref.get().path().path());
    }
    return files;
}

std::vector<SnapshotPath> SnapshotBundle::snapshot_paths() {
    std::vector<SnapshotPath> paths;
    paths.reserve(kSnapshotsCount);

    for (auto& snapshot_ref : snapshots()) {
        paths.push_back(snapshot_ref.get().path());
    }
    return paths;
}

}  // namespace silkworm::snapshots
