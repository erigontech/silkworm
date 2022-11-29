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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wunused-variable"
#if defined(__clang__)
#pragma GCC diagnostic ignored "-Winvalid-constexpr"
#endif /* defined(__clang__) */
#pragma GCC diagnostic ignored "-Wsign-compare"
#include <silkworm/recsplit/function/RecSplit.hpp>
// #include <sux/function/RecSplit.hpp>
#pragma GCC diagnostic pop

#include <silkworm/snapshot/decompressor.hpp>
#include <silkworm/snapshot/repository.hpp>

namespace silkworm {

using namespace sux;
using namespace sux::function;

constexpr std::size_t kLeafSize{8};
using RecSplit8 = RecSplit<kLeafSize>;

class Index {
  public:
    static constexpr uint64_t kPageSize{4096};
    static constexpr std::size_t kBucketSize{2'000};

    explicit Index(SnapshotFile segment_path) : segment_path_(std::move(segment_path)) {}
    virtual ~Index() = default;

    void build();

  protected:
    virtual bool walk(RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) = 0;

    SnapshotFile segment_path_;
};

class HeaderIndex : public Index {
  public:
    explicit HeaderIndex(SnapshotFile path) : Index(std::move(path)) {}

  protected:
    bool walk(RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) override;
};

}  // namespace silkworm
