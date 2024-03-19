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

#include <functional>
#include <utility>

#include <silkworm/db/etl/collector.hpp>
#include <silkworm/db/snapshots/path.hpp>
#include <silkworm/db/snapshots/rec_split/rec_split.hpp>
#include <silkworm/db/snapshots/seg/decompressor.hpp>
#include <silkworm/infra/common/os.hpp>

namespace silkworm::snapshots {

struct IndexDescriptor {
    std::function<Bytes(ByteView word, uint64_t i)> make_key;
    uint64_t base_data_id{};
    bool less_false_positives{};
    size_t etl_buffer_size{db::etl::kOptimalBufferSize};
};

class Index {
  public:
    static inline const auto kPageSize{os::page_size()};
    static constexpr std::size_t kBucketSize{2'000};

    explicit Index(
        IndexDescriptor descriptor,
        SnapshotPath segment_path,
        std::optional<MemoryMappedRegion> segment_region = std::nullopt)
        : descriptor_(std::move(descriptor)),
          segment_path_(std::move(segment_path)),
          segment_region_(segment_region) {}
    virtual ~Index() = default;

    [[nodiscard]] SnapshotPath path() const { return segment_path_.index_file(); }

    virtual void build();

  protected:
    IndexDescriptor descriptor_;
    SnapshotPath segment_path_;
    std::optional<MemoryMappedRegion> segment_region_;
};

class HeaderIndex {
  public:
    static Index make(SnapshotPath segment_path, std::optional<MemoryMappedRegion> segment_region = std::nullopt) {
        return Index{make_descriptor(segment_path), std::move(segment_path), segment_region};
    }

  private:
    static Bytes make_key(ByteView word, uint64_t i);

    static IndexDescriptor make_descriptor(const SnapshotPath& segment_path) {
        return {
            .make_key = HeaderIndex::make_key,
            .base_data_id = segment_path.block_from(),
        };
    }
};

class BodyIndex {
  public:
    static Index make(SnapshotPath segment_path, std::optional<MemoryMappedRegion> segment_region = std::nullopt) {
        return Index{make_descriptor(segment_path), std::move(segment_path), segment_region};
    }

  private:
    static Bytes make_key(ByteView word, uint64_t i);

    static IndexDescriptor make_descriptor(const SnapshotPath& segment_path) {
        return {
            .make_key = BodyIndex::make_key,
            .base_data_id = segment_path.block_from(),
        };
    }

    Index index_;
};

class TransactionIndex1 {
  public:
    static Index make(const SnapshotPath& bodies_segment_path, SnapshotPath segment_path, std::optional<MemoryMappedRegion> segment_region = std::nullopt) {
        auto txs_amount = compute_txs_amount(bodies_segment_path);
        return Index{make_descriptor(txs_amount.first, txs_amount.first, true), std::move(segment_path), segment_region};
    }

    static SnapshotPath bodies_segment_path(const SnapshotPath& segment_path);

  private:
    static Bytes make_key(ByteView word, uint64_t i, uint64_t first_tx_id);
    static std::pair<uint64_t, uint64_t> compute_txs_amount(const SnapshotPath& bodies_segment_path);

    static IndexDescriptor make_descriptor(uint64_t first_tx_id, uint64_t base_data_id, bool less_false_positives) {
        return {
            .make_key = [=](ByteView word, uint64_t i) { return make_key(word, i, first_tx_id); },
            .base_data_id = base_data_id,
            .less_false_positives = less_false_positives,
            .etl_buffer_size = db::etl::kOptimalBufferSize / 2,
        };
    }

    friend class TransactionToBlockIndex;
};

class TransactionToBlockIndex : public Index {
  public:
    TransactionToBlockIndex(const SnapshotPath& bodies_segment_path, SnapshotPath segment_path, std::optional<MemoryMappedRegion> segment_region = std::nullopt)
        : Index(IndexDescriptor{}, std::move(segment_path), segment_region),
          bodies_segment_path_(bodies_segment_path) {
        auto txs_amount = TransactionIndex1::compute_txs_amount(bodies_segment_path);
        const uint64_t first_tx_id = txs_amount.first;
        const uint64_t expected_tx_count = txs_amount.second;

        descriptor_ = TransactionIndex1::make_descriptor(first_tx_id, segment_path_.block_from(), false);
        first_tx_id_ = first_tx_id;
        expected_tx_count_ = expected_tx_count;
    }

    void build() override;

  private:
    uint64_t read_tx_count();

    SnapshotPath bodies_segment_path_;
    uint64_t first_tx_id_{};
    uint64_t expected_tx_count_{};
};

}  // namespace silkworm::snapshots
