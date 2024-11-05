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
    for (auto& segment_ref : segments()) {
        segment_ref.get().reopen_segment();
        ensure(!segment_ref.get().empty(), [&]() {
            return "invalid empty snapshot " + segment_ref.get().fs_path().string();
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
    for (auto& segment_ref : segments()) {
        segment_ref.get().close();
    }
    if (on_close_callback_) {
        on_close_callback_(*this);
    }
}

std::vector<std::filesystem::path> SnapshotBundle::files() {
    std::vector<std::filesystem::path> files;
    files.reserve(kSnapshotsCount + kIndexesCount);

    for (auto& segment_ref : segments()) {
        files.push_back(segment_ref.get().path().path());
    }
    for (auto& index_ref : indexes()) {
        files.push_back(index_ref.get().path().path());
    }
    return files;
}

std::vector<SnapshotPath> SnapshotBundle::segment_paths() {
    std::vector<SnapshotPath> paths;
    paths.reserve(kSnapshotsCount);

    for (auto& segment_ref : segments()) {
        paths.push_back(segment_ref.get().path());
    }
    return paths;
}

std::vector<SnapshotPath> SnapshotBundlePaths::segment_paths() const {
    std::vector<SnapshotPath> results;
    for (auto& entry : schema_.make_segment_paths(dir_path_, step_range_))
        results.push_back(std::move(entry.second));
    return results;
}

std::vector<std::filesystem::path> SnapshotBundlePaths::files() const {
    std::vector<std::filesystem::path> results;
    for (auto& path : schema_.make_all_paths(dir_path_, step_range_))
        results.push_back(path.path());
    return results;
}

}  // namespace silkworm::snapshots
