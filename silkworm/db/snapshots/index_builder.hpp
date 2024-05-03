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

#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <utility>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/db/etl/collector.hpp>
#include <silkworm/db/snapshots/path.hpp>
#include <silkworm/db/snapshots/seg/decompressor.hpp>
#include <silkworm/infra/common/memory_mapped_file.hpp>

namespace silkworm::snapshots {

struct IndexKeyFactory {
    virtual ~IndexKeyFactory() = default;
    virtual Bytes make(ByteView key_data, uint64_t i) = 0;
};

struct IndexDescriptor {
    SnapshotPath index_file;
    std::unique_ptr<IndexKeyFactory> key_factory;
    uint64_t base_data_id{};
    bool double_enum_index{true};
    bool less_false_positives{};
    size_t etl_buffer_size{db::etl::kOptimalBufferSize};
};

struct IndexInputDataQuery {
    class Iterator {
      public:
        struct value_type {
            ByteView key_data;
            uint64_t value{};
        };

        Iterator(IndexInputDataQuery* query, std::shared_ptr<void> impl, value_type entry)
            : query_(query), impl_(std::move(impl)), entry_(entry) {}

        using iterator_category = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = value_type*;
        using reference = value_type&;

        reference operator*() { return entry_; }
        pointer operator->() { return &entry_; }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++();

        friend bool operator!=(const Iterator& lhs, const Iterator& rhs) = default;
        friend bool operator==(const Iterator& lhs, const Iterator& rhs);

      private:
        IndexInputDataQuery* query_;
        std::shared_ptr<void> impl_;
        value_type entry_;
    };

    static_assert(std::input_or_output_iterator<Iterator>);

    virtual ~IndexInputDataQuery() = default;

    virtual Iterator begin() = 0;
    virtual Iterator end() = 0;
    virtual std::size_t keys_count() = 0;
    virtual std::pair<std::shared_ptr<void>, Iterator::value_type> next_iterator(std::shared_ptr<void> it_impl) = 0;
    virtual bool equal_iterators(std::shared_ptr<void> lhs_it_impl, std::shared_ptr<void> rhs_it_impl) const = 0;
};

class DecompressorIndexInputDataQuery : public IndexInputDataQuery {
  public:
    DecompressorIndexInputDataQuery(
        SnapshotPath segment_path,
        std::optional<MemoryMappedRegion> segment_region = std::nullopt)
        : segment_path_(std::move(segment_path)),
          segment_region_(segment_region) {}

    Iterator begin() override;
    Iterator end() override;
    std::size_t keys_count() override;
    std::pair<std::shared_ptr<void>, Iterator::value_type> next_iterator(std::shared_ptr<void> it_impl) override;
    bool equal_iterators(std::shared_ptr<void> lhs_it_impl, std::shared_ptr<void> rhs_it_impl) const override;

  private:
    struct IteratorImpl {
        std::shared_ptr<seg::Decompressor> decoder;
        seg::Decompressor::Iterator it;
    };

    SnapshotPath segment_path_;
    std::optional<MemoryMappedRegion> segment_region_;
};

struct IndexBuilder {
    IndexBuilder(
        IndexDescriptor descriptor,
        std::unique_ptr<IndexInputDataQuery> query)
        : descriptor_(std::move(descriptor)),
          query_(std::move(query)) {}
    virtual ~IndexBuilder() = default;

    IndexBuilder(IndexBuilder&&) = default;
    IndexBuilder& operator=(IndexBuilder&&) = default;

    void build();

    const SnapshotPath& path() const { return descriptor_.index_file; }

  private:
    static constexpr std::size_t kBucketSize{2'000};

    IndexDescriptor descriptor_;
    std::unique_ptr<IndexInputDataQuery> query_;
};

}  // namespace silkworm::snapshots
