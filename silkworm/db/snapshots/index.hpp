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

#include <memory>
#include <utility>

#include <silkworm/db/etl/collector.hpp>
#include <silkworm/db/snapshots/path.hpp>
#include <silkworm/db/snapshots/rec_split/rec_split.hpp>
#include <silkworm/db/snapshots/seg/decompressor.hpp>
#include <silkworm/infra/common/os.hpp>

namespace silkworm::snapshots {

class Index {
  public:
    static inline const auto kPageSize{os::page_size()};
    static constexpr std::size_t kBucketSize{2'000};

    explicit Index(
        SnapshotPath segment_path,
        std::optional<MemoryMappedRegion> segment_region = std::nullopt,
        size_t etl_buffer_size = db::etl::kOptimalBufferSize)
        : segment_path_(std::move(segment_path)),
          segment_region_(segment_region),
          base_data_id_(path().block_from()),
          less_false_positives_(false),
          etl_buffer_size_(etl_buffer_size) {}
    virtual ~Index() = default;

    [[nodiscard]] SnapshotPath path() const { return segment_path_.index_file(); }

    virtual void build();

  protected:
    virtual bool walk(rec_split::RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) = 0;

    SnapshotPath segment_path_;
    std::optional<MemoryMappedRegion> segment_region_;
    uint64_t base_data_id_;
    bool less_false_positives_;
    size_t etl_buffer_size_;
};

class HeaderIndex : public Index {
  public:
    explicit HeaderIndex(SnapshotPath segment_path, std::optional<MemoryMappedRegion> segment_region = {})
        : Index(std::move(segment_path), segment_region) {}

  protected:
    bool walk(rec_split::RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) override;
};

class BodyIndex : public Index {
  public:
    explicit BodyIndex(SnapshotPath segment_path, std::optional<MemoryMappedRegion> segment_region = {})
        : Index(std::move(segment_path), segment_region) {}

  protected:
    bool walk(rec_split::RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) override;
};

class TransactionIndex : public Index {
  public:
    explicit TransactionIndex(SnapshotPath segment_path, std::optional<MemoryMappedRegion> segment_region = {})
        : Index(std::move(segment_path), segment_region) {}

    void build() override;

  protected:
    bool walk(rec_split::RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) override;

  private:
    SnapshotPath bodies_segment_path() const;
    std::pair<uint64_t, uint64_t> compute_txs_amount();
    uint64_t read_tx_count();
};

}  // namespace silkworm::snapshots
