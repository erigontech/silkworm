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

#include <silkworm/node/huffman/decompressor.hpp>
#include <silkworm/node/recsplit/rec_split.hpp>
#include <silkworm/node/snapshot/path.hpp>

namespace silkworm {

class Index {
  public:
    static constexpr uint64_t kPageSize{4096};
    static constexpr std::size_t kBucketSize{2'000};

    explicit Index(SnapshotPath segment_path) : segment_path_(std::move(segment_path)) {}
    virtual ~Index() = default;

    [[nodiscard]] SnapshotPath path() const { return segment_path_.index_file(); }

    virtual void build();

  protected:
    virtual bool walk(succinct::RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) = 0;

    SnapshotPath segment_path_;
};

class HeaderIndex : public Index {
  public:
    explicit HeaderIndex(SnapshotPath segment_path) : Index(std::move(segment_path)) {}

  protected:
    bool walk(succinct::RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) override;
};

class BodyIndex : public Index {
  public:
    explicit BodyIndex(SnapshotPath segment_path) : Index(std::move(segment_path)), uint64_buffer_(8, '\0') {}

  protected:
    bool walk(succinct::RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) override;

  private:
    Bytes uint64_buffer_;
};

class TransactionIndex : public Index {
  public:
    explicit TransactionIndex(SnapshotPath segment_path) : Index(std::move(segment_path)) {}

    void build() override;

  protected:
    bool walk(succinct::RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) override;
};

}  // namespace silkworm
