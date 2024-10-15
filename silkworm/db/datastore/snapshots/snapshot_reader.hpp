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

#include "common/iterator/iterator_read_into_vector.hpp"
#include "seg/decompressor.hpp"
#include "snapshot_path.hpp"
#include "snapshot_word_serializer.hpp"

namespace silkworm::snapshots {

//! \brief Generic snapshot containing data points for a specific block interval [block_from, block_to).
//! \warning The snapshot segment can also be externally managed. This means that the memory-mapping can happen
//! outside of this class and a \code Snapshot instance can be created by specifying the \code MemoryMappedRegion
//! segment containing the information about the memory region already mapped. This must be taken into account
//! because we must avoid to memory-map it again.
class Snapshot {
  public:
    class Iterator {
      public:
        using value_type = std::shared_ptr<SnapshotWordDeserializer>;
        using iterator_category [[maybe_unused]] = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = value_type*;
        using reference = value_type&;

        Iterator(
            seg::Decompressor::Iterator it,
            std::shared_ptr<SnapshotWordDeserializer> deserializer,
            SnapshotPath path)
            : it_(std::move(it)), deserializer_(std::move(deserializer)), path_(std::move(path)) {}

        value_type operator*() const { return deserializer_; }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++();

        Iterator& operator+=(size_t count);

        friend bool operator!=(const Iterator& lhs, const Iterator& rhs) = default;
        friend bool operator==(const Iterator& lhs, const Iterator& rhs);

      private:
        seg::Decompressor::Iterator it_;
        std::shared_ptr<SnapshotWordDeserializer> deserializer_;
        SnapshotPath path_;
    };

    static_assert(std::input_iterator<Iterator>);

    static inline const auto kPageSize{os::page_size()};

    explicit Snapshot(
        SnapshotPath path,
        std::optional<MemoryMappedRegion> segment_region = std::nullopt);
    ~Snapshot();

    Snapshot(Snapshot&&) = default;
    Snapshot& operator=(Snapshot&&) = default;

    const SnapshotPath& path() const { return path_; }
    std::filesystem::path fs_path() const { return path_.path(); }

    bool empty() const { return item_count() == 0; }
    size_t item_count() const { return decoder_.words_count(); }

    MemoryMappedRegion memory_file_region() const;

    void reopen_segment();
    void close();

    Iterator begin(std::shared_ptr<SnapshotWordDeserializer> deserializer) const;
    Iterator end() const;

    Iterator seek(uint64_t offset, std::optional<Hash> hash_prefix, std::shared_ptr<SnapshotWordDeserializer> deserializer) const;

  private:
    seg::Decompressor::Iterator seek_decoder(uint64_t offset, std::optional<Hash> hash_prefix) const;

    //! The path of the segment file for this snapshot
    SnapshotPath path_;

    seg::Decompressor decoder_;
};

template <SnapshotWordDeserializerConcept TWordDeserializer>
class SnapshotReader {
  public:
    class Iterator {
      public:
        using value_type = decltype(TWordDeserializer::value);
        using iterator_category [[maybe_unused]] = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = value_type*;
        using reference = value_type&;

        explicit Iterator(Snapshot::Iterator it)
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
            SnapshotWordDeserializer& base_deserializer = **it_;
            // dynamic_cast is safe because TWordDeserializer was used when creating the Iterator
            auto& s = dynamic_cast<TWordDeserializer&>(base_deserializer);
            return s.value;
        }

        Snapshot::Iterator it_;
    };

    static_assert(std::input_iterator<Iterator>);

    using WordDeserializer = TWordDeserializer;

    explicit SnapshotReader(const Snapshot& snapshot) : snapshot_(snapshot) {}

    Iterator begin() const {
        return Iterator{snapshot_.begin(std::make_shared<TWordDeserializer>())};
    }

    Iterator end() const {
        return Iterator{snapshot_.end()};
    }

    Iterator seek(uint64_t offset, std::optional<Hash> hash_prefix = std::nullopt) const {
        return Iterator{snapshot_.seek(offset, hash_prefix, std::make_shared<TWordDeserializer>())};
    }

    std::optional<typename Iterator::value_type> seek_one(uint64_t offset, std::optional<Hash> hash_prefix = std::nullopt) const {
        auto it = seek(offset, hash_prefix);
        return (it != end()) ? std::optional{std::move(*it)} : std::nullopt;
    }

    std::vector<typename Iterator::value_type> read_into_vector(uint64_t offset, size_t count) const {
        auto it = seek(offset);
        if (it == end()) {
            throw std::runtime_error("SnapshotReader::read_into_vector: bad offset " + std::to_string(offset));
        }
        return iterator_read_into_vector(std::move(it), count);
    }

    const SnapshotPath& path() const { return snapshot_.path(); }

  private:
    const Snapshot& snapshot_;
};

template <class TSnapshotReader>
concept SnapshotReaderConcept = std::same_as<TSnapshotReader, SnapshotReader<typename TSnapshotReader::WordDeserializer>> ||
                                std::derived_from<TSnapshotReader, SnapshotReader<typename TSnapshotReader::WordDeserializer>>;

}  // namespace silkworm::snapshots
