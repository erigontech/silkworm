// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <functional>
#include <vector>

#include "bloom_filter/bloom_filter.hpp"
#include "btree/btree_index.hpp"
#include "common/snapshot_path.hpp"
#include "common/util/iterator/map_values_view.hpp"
#include "domain.hpp"
#include "history.hpp"
#include "inverted_index.hpp"
#include "rec_split/accessor_index.hpp"
#include "schema.hpp"
#include "segment/kv_segment_reader.hpp"
#include "segment/segment_reader.hpp"
#include "segment_and_accessor_index.hpp"

namespace silkworm::snapshots {

struct SnapshotBundleEntityData {
    datastore::EntityMap<segment::SegmentFileReader> segments;
    datastore::EntityMap<segment::KVSegmentFileReader> kv_segments;
    datastore::EntityMap<rec_split::AccessorIndex> accessor_indexes;
    datastore::EntityMap<bloom_filter::BloomFilter> existence_indexes;
    datastore::EntityMap<btree::BTreeIndex> btree_indexes;
};

struct SnapshotBundleData {
    datastore::EntityMap<SnapshotBundleEntityData> entities;
};

SnapshotBundleData open_bundle_data(
    const Schema::RepositoryDef& schema,
    const std::filesystem::path& dir_path,
    datastore::StepRange step_range,
    std::optional<uint32_t> index_salt);

struct SnapshotBundlePaths {
    using StepRange = datastore::StepRange;

    SnapshotBundlePaths(
        Schema::RepositoryDef schema,
        std::filesystem::path dir_path,
        StepRange step_range)
        : schema_{std::move(schema)},
          dir_path_{std::move(dir_path)},
          step_range_{step_range} {}

    StepRange step_range() const { return step_range_; }

    std::vector<std::filesystem::path> files() const;
    datastore::EntityMap<SnapshotPath> segment_paths() const;
    datastore::EntityMap<SnapshotPath> accessor_index_paths() const;

  private:
    Schema::RepositoryDef schema_;
    std::filesystem::path dir_path_;
    StepRange step_range_;
};

struct SnapshotBundle : public SegmentAndAccessorIndexProvider {
    using StepRange = datastore::StepRange;

    SnapshotBundle(StepRange step_range, SnapshotBundleData data)
        : step_range_{step_range},
          data_{std::move(data)} {
    }
    SnapshotBundle(
        const Schema::RepositoryDef& schema,
        const std::filesystem::path& dir_path,
        StepRange range,
        std::optional<uint32_t> index_salt)
        : SnapshotBundle{
              range,
              open_bundle_data(schema, dir_path, range, index_salt),
          } {}
    ~SnapshotBundle() override;

    SnapshotBundle(SnapshotBundle&&) = default;
    SnapshotBundle& operator=(SnapshotBundle&&) noexcept = default;

    auto segments() const {
        return make_map_values_view(data_.entities.at(Schema::kDefaultEntityName).segments);
    }
    const segment::SegmentFileReader& segment(
        datastore::EntityName entity_name,
        datastore::EntityName segment_name) const;
    const rec_split::AccessorIndex& accessor_index(
        datastore::EntityName entity_name,
        datastore::EntityName index_name) const;
    SegmentAndAccessorIndex segment_and_accessor_index(
        const SegmentAndAccessorIndexNames& names) const override {
        return {
            segment(names[0], names[1]),
            accessor_index(names[0], names[2]),
        };
    }

    Domain domain(datastore::EntityName name) const;
    History history(datastore::EntityName name) const;
    InvertedIndex inverted_index(datastore::EntityName name) const;

    StepRange step_range() const { return step_range_; }

    std::vector<std::filesystem::path> files() const;
    std::vector<SnapshotPath> segment_paths() const;

    void on_close(std::function<void(std::vector<std::filesystem::path> files)> callback) {
        on_close_callback_ = std::move(callback);
    }

    const SnapshotBundleData& operator*() const { return data_; }
    const SnapshotBundleData* operator->() const { return &data_; }

  private:
    void close();

    StepRange step_range_;
    SnapshotBundleData data_;
    std::function<void(std::vector<std::filesystem::path> files)> on_close_callback_;
};

}  // namespace silkworm::snapshots
