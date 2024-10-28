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

#include "../common/codec.hpp"
#include "../common/snapshot_path.hpp"
#include "../common/util/iterator/iterator_read_into_vector.hpp"
#include "../seg/decompressor.hpp"

namespace silkworm::snapshots {

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
            SnapshotPath path)
            : it_(std::move(it)), decoder_(std::move(decoder)), path_(std::move(path)) {}

        value_type operator*() const { return decoder_; }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++();

        Iterator& operator+=(size_t count);

        friend bool operator!=(const Iterator& lhs, const Iterator& rhs) = default;
        friend bool operator==(const Iterator& lhs, const Iterator& rhs);

      private:
        seg::Decompressor::Iterator it_;
        std::shared_ptr<Decoder> decoder_;
        SnapshotPath path_;
    };

    static_assert(std::input_iterator<Iterator>);

    static inline const size_t kPageSize{os::page_size()};

    explicit SegmentFileReader(
        SnapshotPath path,
        std::optional<MemoryMappedRegion> segment_region = std::nullopt);
    ~SegmentFileReader();

    SegmentFileReader(SegmentFileReader&&) = default;
    SegmentFileReader& operator=(SegmentFileReader&&) = default;

    const SnapshotPath& path() const { return path_; }
    std::filesystem::path fs_path() const { return path_.path(); }

    bool empty() const { return item_count() == 0; }
    size_t item_count() const { return decompressor_.words_count(); }

    MemoryMappedRegion memory_file_region() const;

    void reopen_segment();
    void close();

    Iterator begin(std::shared_ptr<Decoder> decoder) const;
    Iterator end() const;

    Iterator seek(uint64_t offset, std::optional<Hash> hash_prefix, std::shared_ptr<Decoder> decoder) const;

  private:
    seg::Decompressor::Iterator seek_decompressor(uint64_t offset, std::optional<Hash> hash_prefix) const;

    //! The path of the segment file for this snapshot
    SnapshotPath path_;

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

    using DecoderType = TDecoder;

    explicit SegmentReader(const SegmentFileReader& reader) : reader_(reader) {}

    Iterator begin() const {
        return Iterator{reader_.begin(std::make_shared<TDecoder>())};
    }

    Iterator end() const {
        return Iterator{reader_.end()};
    }

    Iterator seek(uint64_t offset, std::optional<Hash> hash_prefix = std::nullopt) const {
        return Iterator{reader_.seek(offset, hash_prefix, std::make_shared<TDecoder>())};
    }

    std::optional<typename Iterator::value_type> seek_one(uint64_t offset, std::optional<Hash> hash_prefix = std::nullopt) const {
        auto it = seek(offset, hash_prefix);
        return (it != end()) ? std::optional{std::move(*it)} : std::nullopt;
    }

    std::vector<typename Iterator::value_type> read_into_vector(uint64_t offset, size_t count) const {
        auto it = seek(offset);
        if (it == end()) {
            throw std::runtime_error("SegmentReader::read_into_vector: bad offset " + std::to_string(offset));
        }
        return iterator_read_into_vector(std::move(it), count);
    }

    const SnapshotPath& path() const { return reader_.path(); }

  private:
    const SegmentFileReader& reader_;
};

template <class TSegmentReader>
concept SegmentReaderConcept =
    std::same_as<TSegmentReader, SegmentReader<typename TSegmentReader::DecoderType>> ||
    std::derived_from<TSegmentReader, SegmentReader<typename TSegmentReader::DecoderType>>;

}  // namespace silkworm::snapshots
