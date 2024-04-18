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

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/db/snapshots/path.hpp>
#include <silkworm/db/snapshots/settings.hpp>
#include <silkworm/db/snapshots/snapshot.hpp>

namespace silkworm::snapshots {

struct IndexBuilder;

template <typename T>
concept ConcreteSnapshot = std::is_base_of<Snapshot, T>::value;

template <ConcreteSnapshot T>
using SnapshotsByPath = std::map<std::filesystem::path, std::unique_ptr<T>>;

template <ConcreteSnapshot T>
using SnapshotWalker = std::function<bool(const T& snapshot)>;
using HeaderSnapshotWalker = SnapshotWalker<HeaderSnapshot>;
using BodySnapshotWalker = SnapshotWalker<BodySnapshot>;
using TransactionSnapshotWalker = SnapshotWalker<TransactionSnapshot>;

struct SnapshotBundle {
    std::unique_ptr<HeaderSnapshot> headers_snapshot;
    std::unique_ptr<BodySnapshot> bodies_snapshot;
    std::unique_ptr<TransactionSnapshot> tx_snapshot;
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

    [[nodiscard]] BlockNum max_block_available() const { return std::min(segment_max_block_, idx_max_block_); }

    [[nodiscard]] SnapshotPathList get_segment_files() const {
        return get_files(kSegmentExtension);
    }

    void add_snapshot_bundle(SnapshotBundle bundle);

    void reopen_list(const SnapshotPathList& segment_files, bool optimistic = false);
    void reopen_file(const SnapshotPath& segment_path, bool optimistic = false);
    void reopen_folder();
    void close();

    using HeaderWalker = std::function<bool(const BlockHeader& header)>;
    bool for_each_header(const HeaderWalker& fn);

    using BodyWalker = std::function<bool(BlockNum number, const StoredBlockBody& body)>;
    bool for_each_body(const BodyWalker& fn);

    [[nodiscard]] std::size_t header_snapshots_count() const { return header_segments_.size(); }
    [[nodiscard]] std::size_t body_snapshots_count() const { return body_segments_.size(); }
    [[nodiscard]] std::size_t tx_snapshots_count() const { return tx_segments_.size(); }
    [[nodiscard]] std::size_t total_snapshots_count() const {
        return header_snapshots_count() + body_snapshots_count() + tx_snapshots_count();
    }

    [[nodiscard]] std::vector<BlockNumRange> missing_block_ranges() const;
    enum ViewResult {
        kSnapshotNotFound,
        kWalkFailed,
        kWalkSuccess
    };
    ViewResult view_header_segment(BlockNum number, const HeaderSnapshotWalker& walker);
    ViewResult view_body_segment(BlockNum number, const BodySnapshotWalker& walker);
    ViewResult view_tx_segment(BlockNum number, const TransactionSnapshotWalker& walker);

    std::size_t view_header_segments(const HeaderSnapshotWalker& walker);
    std::size_t view_body_segments(const BodySnapshotWalker& walker);
    std::size_t view_tx_segments(const TransactionSnapshotWalker& walker);

    [[nodiscard]] const HeaderSnapshot* get_header_segment(const SnapshotPath& path) const;
    [[nodiscard]] const BodySnapshot* get_body_segment(const SnapshotPath& path) const;
    [[nodiscard]] const TransactionSnapshot* get_tx_segment(const SnapshotPath& path) const;

    [[nodiscard]] const HeaderSnapshot* find_header_segment(BlockNum number) const;
    [[nodiscard]] const BodySnapshot* find_body_segment(BlockNum number) const;
    [[nodiscard]] const TransactionSnapshot* find_tx_segment(BlockNum number) const;

    [[nodiscard]] std::vector<std::shared_ptr<IndexBuilder>> missing_indexes() const;

    [[nodiscard]] BlockNum segment_max_block() const { return segment_max_block_; }
    [[nodiscard]] BlockNum idx_max_block() const { return idx_max_block_; }

    [[nodiscard]] std::optional<BlockNum> find_block_number(Hash txn_hash) const;

  private:
    bool reopen_header(const SnapshotPath& seg_file);
    bool reopen_body(const SnapshotPath& seg_file);
    bool reopen_transaction(const SnapshotPath& seg_file);

    template <ConcreteSnapshot T>
    const T* find_segment(const SnapshotsByPath<T>& segments, BlockNum number) const;

    template <ConcreteSnapshot T>
    static bool reopen(SnapshotsByPath<T>& segments, const SnapshotPath& seg_file);

    [[nodiscard]] SnapshotPathList get_idx_files() const {
        return get_files(kIdxExtension);
    }

    [[nodiscard]] SnapshotPathList get_files(const std::string& ext) const;

    [[nodiscard]] BlockNum max_idx_available() const;

    //! The configuration settings for snapshots
    SnapshotSettings settings_;

    //! All types of .seg files are available - up to this block number
    BlockNum segment_max_block_{0};

    //! All types of .idx files are available - up to this block number
    BlockNum idx_max_block_{0};

    //! The snapshots containing the block Headers
    SnapshotsByPath<HeaderSnapshot> header_segments_;

    //! The snapshots containing the block Bodies
    SnapshotsByPath<BodySnapshot> body_segments_;

    //! The snapshots containing the Transactions
    SnapshotsByPath<TransactionSnapshot> tx_segments_;
};

}  // namespace silkworm::snapshots
