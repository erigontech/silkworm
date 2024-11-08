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

#include <array>
#include <filesystem>
#include <functional>
#include <vector>

#include "common/snapshot_path.hpp"
#include "common/util/iterator/map_values_view.hpp"
#include "domain.hpp"
#include "inverted_index.hpp"
#include "kv_segment/kv_segment_reader.hpp"
#include "rec_split_index/index.hpp"
#include "schema.hpp"
#include "segment/segment_reader.hpp"
#include "segment_and_index.hpp"

namespace silkworm::snapshots {

struct SnapshotBundleEntityData {
    std::map<datastore::EntityName, SegmentFileReader> segments;
    std::map<datastore::EntityName, KVSegmentFileReader> kv_segments;
    std::map<datastore::EntityName, Index> rec_split_indexes;
};

struct SnapshotBundleData {
    std::map<datastore::EntityName, SnapshotBundleEntityData> entities;
};

SnapshotBundleData make_bundle_data(
    const Schema::RepositoryDef& schema,
    const std::filesystem::path& dir_path,
    StepRange step_range);

struct SnapshotBundlePaths {
    SnapshotBundlePaths(
        Schema::RepositoryDef schema,
        std::filesystem::path dir_path,
        StepRange step_range)
        : schema_{std::move(schema)},
          dir_path_{std::move(dir_path)},
          step_range_{step_range} {}

    StepRange step_range() const { return step_range_; }

    std::vector<std::filesystem::path> files() const;
    std::map<datastore::EntityName, SnapshotPath> segment_paths() const;
    std::map<datastore::EntityName, SnapshotPath> rec_split_index_paths() const;

  private:
    Schema::RepositoryDef schema_;
    std::filesystem::path dir_path_;
    StepRange step_range_;
};

struct SnapshotBundle {
    SnapshotBundle(StepRange step_range, SnapshotBundleData data)
        : step_range_{step_range},
          data_{std::move(data)} {
        reopen();
    }
    SnapshotBundle(
        const Schema::RepositoryDef& schema,
        const std::filesystem::path& dir_path,
        StepRange range)
        : SnapshotBundle{
              range,
              make_bundle_data(schema, dir_path, range),
          } {}
    virtual ~SnapshotBundle();

    SnapshotBundle(SnapshotBundle&&) = default;
    SnapshotBundle& operator=(SnapshotBundle&&) noexcept = default;

    auto segments() {
        return make_map_values_view(data_.entities[Schema::kDefaultEntityName].segments);
    }
    const SegmentFileReader& segment(datastore::EntityName name) const;
    const Index& rec_split_index(datastore::EntityName name) const;
    SegmentAndIndex segment_and_rec_split_index(
        std::pair<datastore::EntityName, datastore::EntityName> names) const {
        return {segment(names.first), rec_split_index(names.second)};
    }

    Domain domain(datastore::EntityName name) const;
    InvertedIndex inverted_index(datastore::EntityName name) const;

    StepRange step_range() const { return step_range_; }

    std::vector<std::filesystem::path> files();
    std::vector<SnapshotPath> segment_paths();

    void reopen();
    void close();

    void on_close(std::function<void(SnapshotBundle&)> callback) {
        on_close_callback_ = std::move(callback);
    }

    const SnapshotBundleData& operator*() const { return data_; }
    const SnapshotBundleData* operator->() const { return &data_; }

  private:
    StepRange step_range_;
    SnapshotBundleData data_;
    std::function<void(SnapshotBundle&)> on_close_callback_;
};

}  // namespace silkworm::snapshots
