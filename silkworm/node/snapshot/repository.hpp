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
#include <silkworm/node/snapshot/index.hpp>
#include <silkworm/node/snapshot/path.hpp>
#include <silkworm/node/snapshot/settings.hpp>
#include <silkworm/node/snapshot/snapshot.hpp>

namespace silkworm {

template <typename T>
concept ConcreteSnapshot = std::is_base_of<Snapshot, T>::value;

template <ConcreteSnapshot T>
using SnapshotsByPath = std::map<std::filesystem::path, std::unique_ptr<T>>;

template <ConcreteSnapshot T>
using SnapshotWalker = std::function<bool(const T* snapshot)>;
using HeaderSnapshotWalker = SnapshotWalker<HeaderSnapshot>;
using BodySnapshotWalker = SnapshotWalker<BodySnapshot>;
using TransactionSnapshotWalker = SnapshotWalker<TransactionSnapshot>;

//! Read-only repository for all snapshot files.
//! @details Some simplifications are currently in place:
//! - it opens snapshots only on startup and they are immutable
//! - all snapshots of given blocks range must exist (to make such range available)
//! - gaps in blocks range are not allowed
//! - segments have [from:to) semantic
class SnapshotRepository {
  public:
    explicit SnapshotRepository(SnapshotSettings settings = {});

    [[nodiscard]] BlockNum max_block_available() const { return std::min(segment_max_block_, idx_max_block_); }

    void verify();
    void reopen_folder();

    [[nodiscard]] std::filesystem::path path() const { return settings_.repository_dir; }

    bool for_each_header(const HeaderSnapshot::Walker& fn);
    bool for_each_body(const BodySnapshot::Walker& fn);

    [[nodiscard]] std::size_t header_snapshots_count() const { return header_segments_.size(); }
    [[nodiscard]] std::size_t body_snapshots_count() const { return body_segments_.size(); }
    [[nodiscard]] std::size_t tx_snapshots_count() const { return tx_segments_.size(); }

    [[nodiscard]] std::vector<BlockNumRange> missing_block_ranges() const;
    enum ViewResult {
        kSnapshotNotFound,
        kWalkFailed,
        kWalkSuccess
    };
    ViewResult view_header_segment(BlockNum number, const HeaderSnapshotWalker& walker);
    ViewResult view_body_segment(BlockNum number, const BodySnapshotWalker& walker);
    ViewResult view_tx_segment(BlockNum number, const TransactionSnapshotWalker& walker);

    [[nodiscard]] std::vector<std::shared_ptr<Index>> missing_indexes() const;

    [[nodiscard]] BlockNum segment_max_block() const { return segment_max_block_; }
    [[nodiscard]] BlockNum idx_max_block() const { return idx_max_block_; }

  private:
    void reopen_list(const SnapshotPathList& segment_files, bool optimistic);

    bool reopen_header(const SnapshotPath& seg_file);
    bool reopen_body(const SnapshotPath& seg_file);
    bool reopen_transaction(const SnapshotPath& seg_file);

    void close_segments_not_in_list(const SnapshotPathList& segment_files);

    template <ConcreteSnapshot T>
    static ViewResult view(const SnapshotsByPath<T>& segments, BlockNum number, const SnapshotWalker<T>& walker);

    template <ConcreteSnapshot T>
    static bool reopen(SnapshotsByPath<T>& segments, const SnapshotPath& seg_file);

    [[nodiscard]] SnapshotPathList get_segment_files() const {
        return get_files(kSegmentExtension);
    }

    [[nodiscard]] SnapshotPathList get_idx_files() const {
        return get_files(kIdxExtension);
    }

    [[nodiscard]] SnapshotPathList get_files(const std::string& ext) const;

    [[nodiscard]] uint64_t max_idx_available() const;

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

}  // namespace silkworm
