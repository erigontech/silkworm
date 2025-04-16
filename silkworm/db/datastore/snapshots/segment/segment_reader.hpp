// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <concepts>
#include <cstdint>
#include <filesystem>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/infra/common/memory_mapped_file.hpp>
#include <silkworm/infra/common/os.hpp>

#include "../../common/step_timestamp_converter.hpp"
#include "../common/codec.hpp"
#include "../common/snapshot_path.hpp"
#include "../common/util/iterator/iterator_read_into_vector.hpp"
#include "seg/decompressor.hpp"

namespace silkworm::snapshots::segment {

/**
 * SegmentFileReader is a type-safe wrapper on top of a seg::Decompressor.
 *
 * The type-safe mechanism is based on Decoder interface.
 * SegmentFileReader can be bound with any Decoder.
 * SegmentFileReader is a template-free counterpart of SegmentReader.
 * Use a SegmentReader for simple type-safe access to the data.
 * SegmentFileReader can work with an externally owned MemoryMappedRegion if provided,
 * otherwise the internal seg::Decompressor owns the memory mapped file.
 */
class SegmentFileReader {
  public:
    class Iterator {
      public:
        using value_type = std::shared_ptr<Decoder>;
        using iterator_category [[maybe_unused]] = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = value_type*;
        using reference = value_type&;

        Iterator(
            seg::Decompressor::Iterator it,
            std::shared_ptr<Decoder> decoder,
            SnapshotPath path,
            datastore::StepToTimestampConverter step_converter)
            : it_(std::move(it)),
              decoder_(std::move(decoder)),
              path_(std::move(path)),
              step_converter_(std::move(step_converter)) {}

        Iterator()
            : it_{seg::Decompressor::Iterator::make_end()},
              decoder_{},
              path_{std::nullopt},
              step_converter_{} {}

        value_type operator*() const { return decoder_; }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++();

        Iterator& operator+=(size_t count);

        friend bool operator!=(const Iterator& lhs, const Iterator& rhs) = default;
        friend bool operator==(const Iterator& lhs, const Iterator& rhs);

      private:
        seg::Decompressor::Iterator it_;
        std::shared_ptr<Decoder> decoder_;
        std::optional<SnapshotPath> path_;
        datastore::StepToTimestampConverter step_converter_;
    };

    static_assert(std::input_iterator<Iterator>);
    static_assert(std::sentinel_for<Iterator, Iterator>);

    static inline const size_t kPageSize{os::page_size()};

    explicit SegmentFileReader(
        SnapshotPath path,
        datastore::StepToTimestampConverter step_converter,
        std::optional<MemoryMappedRegion> segment_region = std::nullopt,
        bool is_compressed = true);

    SegmentFileReader(SegmentFileReader&&) = default;
    SegmentFileReader& operator=(SegmentFileReader&&) = default;

    const SnapshotPath& path() const { return path_; }
    const std::filesystem::path& fs_path() const { return path_.path(); }

    bool empty() const { return item_count() == 0; }
    size_t item_count() const { return decompressor_.words_count(); }

    MemoryMappedRegion memory_file_region() const;

    Iterator begin(std::shared_ptr<Decoder> decoder) const;
    Iterator end() const;

    Iterator seek(uint64_t offset, std::optional<ByteView> check_prefix, std::shared_ptr<Decoder> decoder) const;

  private:
    //! The path of the segment file for this snapshot
    SnapshotPath path_;
    datastore::StepToTimestampConverter step_converter_;

    seg::Decompressor decompressor_;
};

template <DecoderConcept TDecoder>
class SegmentReader {
  public:
    class Iterator {
      public:
        using value_type = decltype(TDecoder::value);
        using iterator_category [[maybe_unused]] = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = value_type*;
        using reference = value_type&;

        explicit Iterator(SegmentFileReader::Iterator it)
            : it_(std::move(it)) {}

        Iterator() = default;

        reference operator*() const { return value(); }
        pointer operator->() const { return &value(); }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++() {
            ++it_;
            return *this;
        }

        Iterator& operator+=(size_t count) {
            it_ += count;
            return *this;
        }

        friend bool operator!=(const Iterator& lhs, const Iterator& rhs) = default;
        friend bool operator==(const Iterator& lhs, const Iterator& rhs) = default;

      private:
        value_type& value() const {
            Decoder& base_decoder = **it_;
            // dynamic_cast is safe because TDecoder was used when creating the Iterator
            auto& decoder = dynamic_cast<TDecoder&>(base_decoder);
            return decoder.value;
        }

        SegmentFileReader::Iterator it_;
    };

    static_assert(std::input_iterator<Iterator>);
    static_assert(std::sentinel_for<Iterator, Iterator>);

    using DecoderType = TDecoder;

    explicit SegmentReader(const SegmentFileReader& reader) : reader_{&reader} {}

    Iterator begin() const {
        return Iterator{reader_->begin(std::make_shared<TDecoder>())};
    }

    Iterator end() const {
        return Iterator{reader_->end()};
    }

    Iterator seek(uint64_t offset, std::optional<ByteView> check_prefix = std::nullopt) const {
        return Iterator{reader_->seek(offset, check_prefix, std::make_shared<TDecoder>())};
    }

    std::optional<typename Iterator::value_type> seek_one(uint64_t offset, std::optional<ByteView> check_prefix = std::nullopt) const {
        auto it = seek(offset, check_prefix);
        return (it != end()) ? std::optional{std::move(*it)} : std::nullopt;
    }

    std::vector<typename Iterator::value_type> read_into_vector(uint64_t offset, size_t count) const {
        auto it = seek(offset);
        if (it == end()) {
            throw std::runtime_error("SegmentReader::read_into_vector: bad offset " + std::to_string(offset));
        }
        return iterator_read_into_vector(std::move(it), count);
    }

    const SnapshotPath& path() const { return reader_->path(); }

  private:
    const SegmentFileReader* reader_;
};

template <class TSegmentReader>
concept SegmentReaderConcept =
    std::same_as<TSegmentReader, SegmentReader<typename TSegmentReader::DecoderType>> ||
    std::derived_from<TSegmentReader, SegmentReader<typename TSegmentReader::DecoderType>>;

}  // namespace silkworm::snapshots::segment
