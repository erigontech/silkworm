// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <filesystem>
#include <iterator>
#include <memory>
#include <optional>
#include <utility>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/common/memory_mapped_file.hpp>

#include "../elias_fano/elias_fano_list.hpp"
#include "../segment/kv_segment_reader.hpp"
#include "btree.hpp"

namespace silkworm::snapshots::btree {

class BTreeIndex {
  public:
    static constexpr uint64_t kDefaultFanout{256};

    using DataIndex = BTree::DataIndex;
    using EliasFanoList32 = elias_fano::EliasFanoList32;
    using KVSegmentReader = segment::KVSegmentFileReader;

    class Cursor {
      public:
        using value_type = std::pair<BytesOrByteView, BytesOrByteView>;
        using iterator_category [[maybe_unused]] = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = value_type*;
        using reference = value_type&;

        Cursor() = default;

        ByteView key() const noexcept { return value_.first; }
        ByteView value() const noexcept { return value_.second; }
        DataIndex data_index() const noexcept { return data_index_; }

        bool next();

        reference operator*() const { return value_; }
        pointer operator->() const { return &value_; }

        Cursor operator++(int) { return std::exchange(*this, ++Cursor{*this}); }
        Cursor& operator++() {
            if (!next()) {
                // reset to the end state
                *this = {};
            }
            return *this;
        }

        friend bool operator!=(const Cursor& it, const std::default_sentinel_t&) {
            return it.index_ != nullptr;
        }
        friend bool operator==(const Cursor& it, const std::default_sentinel_t&) {
            return it.index_ == nullptr;
        }
        friend bool operator!=(const std::default_sentinel_t& s, const Cursor& it) {
            return it != s;
        }
        friend bool operator==(const std::default_sentinel_t& s, const Cursor& it) {
            return it == s;
        }

      private:
        friend class BTreeIndex;

        Cursor(
            const BTreeIndex* index,
            BytesOrByteView key,
            BytesOrByteView value,
            DataIndex data_index,
            const KVSegmentReader* kv_segment)
            : index_{index},
              value_{std::move(key), std::move(value)},
              data_index_{data_index},
              kv_segment_{kv_segment} {}

        const BTreeIndex* index_{nullptr};
        mutable value_type value_;
        DataIndex data_index_{0};
        const KVSegmentReader* kv_segment_{nullptr};
    };

    explicit BTreeIndex(
        std::filesystem::path index_file_path,
        std::optional<MemoryMappedRegion> index_region = {},
        uint64_t btree_fanout = kDefaultFanout);

    void warmup_if_empty_or_check(const KVSegmentReader& kv_segment);

    //! Return the Elias-Fano encoding of the sequence of key offsets or nullptr if not present
    std::shared_ptr<EliasFanoList32> data_offsets() const { return data_offsets_; }

    //! Return the number of keys included into this index
    size_t key_count() const { return data_offsets_->size(); };

    const std::filesystem::path& path() const { return file_path_; }

    MemoryMappedRegion memory_file_region() const;

    //! Seek and return a cursor at position where key >= \p seek_key
    //! \param seek_key the given key at/after which the cursor must be positioned
    //! \param kv_segment reader of the key-value data sequence
    //! \return a cursor positioned at key >= \p seek_key or nullptr
    //! \details if \p seek_key is empty, first key is returned
    //! \details if \p seek_key is greater than any other key, std::nullopt is returned
    std::optional<Cursor> seek(ByteView seek_key, const KVSegmentReader& kv_segment) const;

    //! Get the value associated to the given key with exact match
    //! \param key the data key to match exactly
    //! \param kv_segment reader of the key-value data sequence
    //! \return the value associated at \p key or std::nullopt if not found
    std::optional<BytesOrByteView> get(ByteView key, const KVSegmentReader& kv_segment) const;

  private:
    class KeyValueIndex : public BTree::KeyValueIndex {
      public:
        explicit KeyValueIndex(
            const KVSegmentReader& kv_segment,
            std::shared_ptr<EliasFanoList32> data_offsets,
            const std::filesystem::path& file_path)
            : kv_segment_{kv_segment},
              data_offsets_{std::move(data_offsets)},
              file_path_{file_path} {}
        ~KeyValueIndex() override = default;

        std::optional<BTree::KeyValue> lookup_key_value(DataIndex data_index) const override;
        std::optional<BytesOrByteView> lookup_key(DataIndex data_index) const override;
        std::optional<LookupResult> lookup_key_value(DataIndex, ByteView) const override;
        std::optional<BytesOrByteView> advance_key_value(DataIndex, ByteView, size_t skip_max_count) const override;

      private:
        const KVSegmentReader& kv_segment_;
        std::shared_ptr<EliasFanoList32> data_offsets_;
        const std::filesystem::path& file_path_;
    };

    std::filesystem::path file_path_;
    std::unique_ptr<MemoryMappedFile> memory_file_;
    std::shared_ptr<EliasFanoList32> data_offsets_;
    std::unique_ptr<BTree> btree_;
};

}  // namespace silkworm::snapshots::btree
