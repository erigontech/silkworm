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

#include <silkworm/infra/concurrency/thread_pool.hpp>
#include <silkworm/node/huffman/decompressor.hpp>
#include <silkworm/node/recsplit/rec_split.hpp>
#include <silkworm/node/snapshot/path.hpp>
#include <silkworm/node/test/snapshots.hpp>

namespace silkworm::snapshot {

using RecSplitSettings = succinct::RecSplitSettings;
using RecSplit8 = succinct::RecSplit8;

class Index {
  public:
    static constexpr uint64_t kPageSize{4096};
    static constexpr std::size_t kBucketSize{2'000};

    explicit Index(SnapshotPath segment_path, std::optional<MemoryMappedRegion> segment_region = {})
        : segment_path_(std::move(segment_path)), segment_region_{std::move(segment_region)} {}
    virtual ~Index() = default;

    [[nodiscard]] SnapshotPath path() const { return segment_path_.index_file(); }

    virtual void build();

  protected:
    virtual bool walk(RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) = 0;

    struct Slice {
        uint64_t ordinal;
        uint64_t offset;
    };

    using ExtractOrdinal = std::function<uint64_t(Snapshot::WordItem&)>;
    std::vector<Index::Slice> prefetch_offsets(huffman::Decompressor& decoder, ExtractOrdinal = nullptr);

    static uint64_t closest_offset(const std::vector<Index::Slice>& sorted_slices, uint64_t target_ordinal);

    ThreadPool thread_pool_{std::thread::hardware_concurrency()};
    SnapshotPath segment_path_;
    std::optional<MemoryMappedRegion> segment_region_;
};

class HeaderIndex : public Index {
  public:
    explicit HeaderIndex(SnapshotPath segment_path, std::optional<MemoryMappedRegion> segment_region = {})
        : Index(std::move(segment_path), std::move(segment_region)) {}

  protected:
    bool walk(RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) override;
};

class BodyIndex : public Index {
  public:
    explicit BodyIndex(SnapshotPath segment_path, std::optional<MemoryMappedRegion> segment_region = {})
        : Index(std::move(segment_path), std::move(segment_region)), uint64_buffer_(8, '\0') {}

  protected:
    bool walk(RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) override;

  private:
    Bytes uint64_buffer_;
};

class TransactionIndex : public Index {
  public:
    explicit TransactionIndex(SnapshotPath segment_path, std::optional<MemoryMappedRegion> segment_region = {})
        : Index(std::move(segment_path), std::move(segment_region)) {}

    void build() override;

  protected:
    bool walk(RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) override;
};

}  // namespace silkworm::snapshot
