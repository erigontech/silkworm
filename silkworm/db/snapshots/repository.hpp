/*
   Copyright 2022 The Silkworm Authors

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
#include <cassert>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/db/snapshots/index.hpp>
#include <silkworm/db/snapshots/path.hpp>
#include <silkworm/db/snapshots/settings.hpp>
#include <silkworm/db/snapshots/snapshot_reader.hpp>

namespace silkworm::snapshots {

struct IndexBuilder;

struct SnapshotBundle {
    Snapshot header_snapshot;
    //! Index header_hash -> block_num -> headers_segment_offset
    Index idx_header_hash;

    Snapshot body_snapshot;
    //! Index block_num -> bodies_segment_offset
    Index idx_body_number;

    Snapshot txn_snapshot;
    //! Index transaction_hash -> txn_id -> transactions_segment_offset
    Index idx_txn_hash;
    //! Index transaction_hash -> block_num
    Index idx_txn_hash_2_block;

    std::array<std::reference_wrapper<Snapshot>, 3> snapshots() {
        return {
            header_snapshot,
            body_snapshot,
            txn_snapshot,
        };
    }

    std::array<std::reference_wrapper<Index>, 4> indexes() {
        return {
            idx_header_hash,
            idx_body_number,
            idx_txn_hash,
            idx_txn_hash_2_block,
        };
    }

    const Snapshot& snapshot(SnapshotType type) const {
        switch (type) {
            case headers:
                return header_snapshot;
            case bodies:
                return body_snapshot;
            case transactions:
            case transactions_to_block:
                return txn_snapshot;
        }
        assert(false);
        return header_snapshot;
    }

    const Index& index(SnapshotType type) const {
        switch (type) {
            case headers:
                return idx_header_hash;
            case bodies:
                return idx_body_number;
            case transactions:
                return idx_txn_hash;
            case transactions_to_block:
                return idx_txn_hash_2_block;
        }
        assert(false);
        return idx_header_hash;
    }

    // assume that all snapshots have the same block range, and use one of them
    BlockNum block_from() const { return header_snapshot.block_from(); }
    BlockNum block_to() const { return header_snapshot.block_to(); }
};

//! Read-only repository for all snapshot files.
//! @details Some simplifications are currently in place:
//! - it opens snapshots only on startup and they are immutable
//! - all snapshots of given blocks range must exist (to make such range available)
//! - gaps in blocks range are not allowed
//! - segments have [from:to) semantic
class SnapshotRepository {
  public:
    explicit SnapshotRepository(const SnapshotSettings& settings = {});
    ~SnapshotRepository();

    [[nodiscard]] const SnapshotSettings& settings() const { return settings_; }
    [[nodiscard]] std::filesystem::path path() const { return settings_.repository_dir; }

    void reopen_folder();
    void close();

    void add_snapshot_bundle(SnapshotBundle bundle);

    [[nodiscard]] std::size_t header_snapshots_count() const { return bundles_.size(); }
    [[nodiscard]] std::size_t body_snapshots_count() const { return bundles_.size(); }
    [[nodiscard]] std::size_t tx_snapshots_count() const { return bundles_.size(); }
    [[nodiscard]] std::size_t total_snapshots_count() const {
        return header_snapshots_count() + body_snapshots_count() + tx_snapshots_count();
    }

    [[nodiscard]] BlockNum segment_max_block() const { return segment_max_block_; }
    [[nodiscard]] BlockNum idx_max_block() const { return idx_max_block_; }
    [[nodiscard]] BlockNum max_block_available() const { return std::min(segment_max_block_, idx_max_block_); }

    [[nodiscard]] std::vector<BlockNumRange> missing_block_ranges() const;
    [[nodiscard]] std::vector<std::shared_ptr<IndexBuilder>> missing_indexes() const;

    struct SnapshotAndIndex {
        const Snapshot& snapshot;
        const Index& index;
    };

    using SnapshotWalker = std::function<bool(SnapshotAndIndex result)>;

    using SnapshotBundleWalker = std::function<bool(const SnapshotBundle& bundle)>;
    std::size_t view_bundles(const SnapshotBundleWalker& walker);

    std::size_t view_header_segments(const SnapshotWalker& walker);
    std::size_t view_body_segments(const SnapshotWalker& walker);
    std::size_t view_tx_segments(const SnapshotWalker& walker);

    [[nodiscard]] std::optional<SnapshotAndIndex> find_header_segment(BlockNum number) const;
    [[nodiscard]] std::optional<SnapshotAndIndex> find_body_segment(BlockNum number) const;
    [[nodiscard]] std::optional<SnapshotAndIndex> find_tx_segment(BlockNum number) const;

    using HeaderWalker = std::function<bool(const BlockHeader& header)>;
    bool for_each_header(const HeaderWalker& fn);

    using BodyWalker = std::function<bool(BlockNum number, const BlockBodyForStorage& body)>;
    bool for_each_body(const BodyWalker& fn);

    [[nodiscard]] std::optional<BlockNum> find_block_number(Hash txn_hash) const;

  private:
    void reopen_list(const SnapshotPathList& segment_files);
    std::size_t view_segments(SnapshotType type, const SnapshotWalker& walker);
    const SnapshotBundle* find_bundle(BlockNum number) const;
    std::optional<SnapshotRepository::SnapshotAndIndex> find_segment(SnapshotType type, BlockNum number) const;

    [[nodiscard]] SnapshotPathList get_segment_files() const {
        return get_files(kSegmentExtension);
    }

    [[nodiscard]] SnapshotPathList get_idx_files() const {
        return get_files(kIdxExtension);
    }

    [[nodiscard]] SnapshotPathList get_files(const std::string& ext) const;

    [[nodiscard]] BlockNum max_idx_available();

    //! The configuration settings for snapshots
    SnapshotSettings settings_;

    //! All types of .seg files are available - up to this block number
    BlockNum segment_max_block_{0};

    //! All types of .idx files are available - up to this block number
    BlockNum idx_max_block_{0};

    //! Full snapshot bundles ordered by block_from
    std::map<BlockNum, SnapshotBundle> bundles_;
};

}  // namespace silkworm::snapshots
