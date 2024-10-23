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

#include <silkworm/core/common/assert.hpp>

#include "common/snapshot_path.hpp"
#include "rec_split_index/index.hpp"
#include "segment/segment_reader.hpp"
#include "segment_and_index.hpp"

namespace silkworm::snapshots {

struct SnapshotBundleData {
    SegmentFileReader header_segment;
    //! Index header_hash -> block_num -> headers_segment_offset
    Index idx_header_hash;

    SegmentFileReader body_segment;
    //! Index block_num -> bodies_segment_offset
    Index idx_body_number;

    SegmentFileReader txn_segment;
    //! Index transaction_hash -> txn_id -> transactions_segment_offset
    Index idx_txn_hash;
    //! Index transaction_hash -> block_num
    Index idx_txn_hash_2_block;

    static constexpr size_t kSnapshotsCount = 3;
    static constexpr size_t kIndexesCount = 4;
};

struct SnapshotBundle : public SnapshotBundleData {
    explicit SnapshotBundle(StepRange step_range, SnapshotBundleData bundle)
        : SnapshotBundleData{std::move(bundle)},
          step_range_{step_range} {}
    virtual ~SnapshotBundle();

    SnapshotBundle(SnapshotBundle&&) = default;
    SnapshotBundle& operator=(SnapshotBundle&&) noexcept = default;

    std::array<std::reference_wrapper<SegmentFileReader>, kSnapshotsCount> segments() {
        return {
            header_segment,
            body_segment,
            txn_segment,
        };
    }

    std::array<std::reference_wrapper<Index>, kIndexesCount> indexes() {
        return {
            idx_header_hash,
            idx_body_number,
            idx_txn_hash,
            idx_txn_hash_2_block,
        };
    }

    std::array<SnapshotType, kSnapshotsCount> snapshot_types() {
        return {
            SnapshotType::headers,
            SnapshotType::bodies,
            SnapshotType::transactions,
        };
    }

    std::array<SnapshotType, kIndexesCount> index_types() {
        return {
            SnapshotType::headers,
            SnapshotType::bodies,
            SnapshotType::transactions,
            SnapshotType::transactions_to_block,
        };
    }

    const SegmentFileReader& segment(SnapshotType type) const {
        switch (type) {
            case headers:
                return header_segment;
            case bodies:
                return body_segment;
            case transactions:
            case transactions_to_block:
                return txn_segment;
        }
        SILKWORM_ASSERT(false);
        return header_segment;
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
        SILKWORM_ASSERT(false);
        return idx_header_hash;
    }

    SegmentAndIndex segment_and_index(SnapshotType type) const {
        return {segment(type), index(type)};
    }

    StepRange step_range() const { return step_range_; }

    std::vector<std::filesystem::path> files();
    std::vector<SnapshotPath> snapshot_paths();

    void reopen();
    void close();

    void on_close(std::function<void(SnapshotBundle&)> callback) {
        on_close_callback_ = std::move(callback);
    }

  private:
    StepRange step_range_;
    std::function<void(SnapshotBundle&)> on_close_callback_;
};

}  // namespace silkworm::snapshots
