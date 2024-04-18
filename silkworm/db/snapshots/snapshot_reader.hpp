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

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/db/snapshots/path.hpp>
#include <silkworm/db/snapshots/seg/decompressor.hpp>
#include <silkworm/infra/common/memory_mapped_file.hpp>
#include <silkworm/infra/common/os.hpp>

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
        using value_type = std::shared_ptr<SnapshotWordSerializer>;
        using iterator_category = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = const value_type*;
        using reference = const value_type&;

        Iterator(
            seg::Decompressor::Iterator it,
            std::shared_ptr<SnapshotWordSerializer> serializer,
            SnapshotPath path)
            : it_(std::move(it)), serializer_(std::move(serializer)), path_(std::move(path)) {}

        reference operator*() const { return serializer_; }
        pointer operator->() const { return &serializer_; }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++();

        friend bool operator!=(const Iterator& lhs, const Iterator& rhs) = default;
        friend bool operator==(const Iterator& lhs, const Iterator& rhs);

      private:
        seg::Decompressor::Iterator it_;
        std::shared_ptr<SnapshotWordSerializer> serializer_;
        SnapshotPath path_;
    };

    static_assert(std::input_iterator<Iterator>);

    static inline const auto kPageSize{os::page_size()};

    explicit Snapshot(SnapshotPath path, std::optional<MemoryMappedRegion> segment_region = std::nullopt);
    virtual ~Snapshot() = default;

    [[nodiscard]] SnapshotPath path() const { return path_; }
    [[nodiscard]] std::filesystem::path fs_path() const { return path_.path(); }

    [[nodiscard]] BlockNum block_from() const { return path_.block_from(); }
    [[nodiscard]] BlockNum block_to() const { return path_.block_to(); }

    [[nodiscard]] bool empty() const { return item_count() == 0; }
    [[nodiscard]] std::size_t item_count() const { return decoder_.words_count(); }

    [[nodiscard]] MemoryMappedRegion memory_file_region() const;

    void reopen_segment();
    virtual void reopen_index() = 0;

    Iterator begin(std::shared_ptr<SnapshotWordSerializer> serializer) const;
    Iterator end() const;

    Iterator seek(uint64_t offset, std::optional<Hash> hash_prefix, std::shared_ptr<SnapshotWordSerializer> serializer) const;

    void close();

  protected:
    void close_segment();
    virtual void close_index() = 0;
    seg::Decompressor::Iterator seek_decoder(uint64_t offset, std::optional<Hash> hash_prefix) const;

    //! The path of the segment file for this snapshot
    SnapshotPath path_;

    seg::Decompressor decoder_;
};

template <class TWordSerializer>
class SnapshotReader {
  public:
    class Iterator {
      public:
        using value_type = decltype(TWordSerializer::value);
        using iterator_category = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = const value_type*;
        using reference = const value_type&;

        explicit Iterator(Snapshot::Iterator it)
            : it_(std::move(it)) {}

        reference operator*() const { return value(); }
        pointer operator->() const { return &value(); }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++() {
            ++it_;
            return *this;
        }

        friend bool operator!=(const Iterator& lhs, const Iterator& rhs) = default;
        friend bool operator==(const Iterator& lhs, const Iterator& rhs) = default;

      private:
        value_type& value() const {
            SnapshotWordSerializer& base_serializer = **it_;
            // dynamic_cast is safe because TWordSerializer was used when creating the Iterator
            auto& s = dynamic_cast<TWordSerializer&>(base_serializer);
            return s.value;
        }

        Snapshot::Iterator it_;
    };

    static_assert(std::input_iterator<Iterator>);

    SnapshotReader(const Snapshot& snapshot) : snapshot_(snapshot) {}

    Iterator begin() const {
        return Iterator{snapshot_.begin(std::make_shared<TWordSerializer>())};
    }

    Iterator end() const {
        return Iterator{snapshot_.end()};
    }

    Iterator seek(uint64_t offset, std::optional<Hash> hash_prefix = std::nullopt) const {
        return Iterator{snapshot_.seek(offset, hash_prefix, std::make_shared<TWordSerializer>())};
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

    [[nodiscard]] BlockNum block_from() const { return snapshot_.block_from(); }
    [[nodiscard]] BlockNum block_to() const { return snapshot_.block_to(); }

  private:
    const Snapshot& snapshot_;
};

template <std::input_iterator It>
void iterator_read_into(It it, size_t count, std::vector<typename It::value_type>& out) {
    std::copy_n(std::make_move_iterator(std::move(it)), count, std::back_inserter(out));
}

template <std::input_iterator It>
std::vector<typename It::value_type> iterator_read_into_vector(It it, size_t count) {
    std::vector<typename It::value_type> out;
    out.reserve(count);
    iterator_read_into(std::move(it), count, out);
    return out;
}

}  // namespace silkworm::snapshots
