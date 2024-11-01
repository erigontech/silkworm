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

class KVSegmentFileReader {
  public:
    class Iterator {
      public:
        using value_type = std::pair<std::shared_ptr<Decoder>, std::shared_ptr<Decoder>>;
        using iterator_category [[maybe_unused]] = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = value_type*;
        using reference = value_type&;

        Iterator(
            seg::Decompressor::Iterator it,
            std::shared_ptr<Decoder> key_decoder,
            std::shared_ptr<Decoder> value_decoder,
            SnapshotPath path)
            : it_(std::move(it)),
              decoders_(std::move(key_decoder), std::move(value_decoder)),
              path_(std::move(path)) {}

        value_type operator*() const { return decoders_; }
        const value_type* operator->() const { return &decoders_; }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++();

        Iterator& operator+=(size_t count);

        friend bool operator!=(const Iterator& lhs, const Iterator& rhs) = default;
        friend bool operator==(const Iterator& lhs, const Iterator& rhs);

      private:
        seg::Decompressor::Iterator it_;
        value_type decoders_;
        SnapshotPath path_;
    };

    static_assert(std::input_iterator<Iterator>);

    static inline const size_t kPageSize{os::page_size()};

    explicit KVSegmentFileReader(
        SnapshotPath path,
        seg::CompressionKind compression_kind,
        std::optional<MemoryMappedRegion> segment_region = std::nullopt);
    ~KVSegmentFileReader();

    KVSegmentFileReader(KVSegmentFileReader&&) = default;
    KVSegmentFileReader& operator=(KVSegmentFileReader&&) = default;

    const SnapshotPath& path() const { return path_; }
    std::filesystem::path fs_path() const { return path_.path(); }

    bool empty() const { return item_count() == 0; }
    size_t item_count() const { return decompressor_.words_count(); }

    MemoryMappedRegion memory_file_region() const;

    void reopen_segment();
    void close();

    Iterator begin(std::shared_ptr<Decoder> key_decoder, std::shared_ptr<Decoder> value_decoder) const;
    Iterator end() const;

    Iterator seek(
        uint64_t offset,
        std::optional<Hash> hash_prefix,
        std::shared_ptr<Decoder> key_decoder,
        std::shared_ptr<Decoder> value_decoder) const;

  private:
    seg::Decompressor::Iterator seek_decompressor(uint64_t offset, std::optional<Hash> hash_prefix) const;

    //! The path of the segment file for this snapshot
    SnapshotPath path_;

    seg::Decompressor decompressor_;
};

template <DecoderConcept TKeyDecoder, DecoderConcept TValueDecoder>
class KVSegmentReader {
  public:
    class Iterator {
      public:
        using value_type_owned = std::pair<decltype(TKeyDecoder::value), decltype(TValueDecoder::value)>;
        using value_type = std::pair<decltype(TKeyDecoder::value)&, decltype(TValueDecoder::value)&>;
        using iterator_category [[maybe_unused]] = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = value_type*;
        using reference = value_type&;

        explicit Iterator(KVSegmentFileReader::Iterator it)
            : it_(std::move(it)) {}

        value_type operator*() const { return value(); }

        value_type_owned move_value() const {
            value_type value = this->value();
            return {std::move(value.first), std::move(value.second)};
        }

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
        value_type value() const {
            Decoder& base_key_decoder = *(it_->first);
            Decoder& base_value_decoder = *(it_->second);
            // dynamic_cast is safe because TKeyDecoder was used when creating the Iterator
            auto& key_decoder = dynamic_cast<TKeyDecoder&>(base_key_decoder);
            // dynamic_cast is safe because TValueDecoder was used when creating the Iterator
            auto& key_value_decoder = dynamic_cast<TValueDecoder&>(base_value_decoder);
            return {key_decoder.value, key_value_decoder.value};
        }

        KVSegmentFileReader::Iterator it_;
    };

    static_assert(std::input_iterator<Iterator>);

    using KeyDecoderType = TKeyDecoder;
    using ValueDecoderType = TValueDecoder;

    explicit KVSegmentReader(const KVSegmentFileReader& reader) : reader_(reader) {}

    Iterator begin() const {
        return Iterator{reader_.begin(std::make_shared<TKeyDecoder>(), std::make_shared<TValueDecoder>())};
    }

    Iterator end() const {
        return Iterator{reader_.end()};
    }

    Iterator seek(uint64_t offset, std::optional<Hash> hash_prefix = std::nullopt) const {
        return Iterator{reader_.seek(offset, hash_prefix, std::make_shared<TKeyDecoder>(), std::make_shared<TValueDecoder>())};
    }

    std::optional<typename Iterator::value_type_owned> seek_one(uint64_t offset, std::optional<Hash> hash_prefix = std::nullopt) const {
        auto it = seek(offset, hash_prefix);
        auto& [key, value] = *it;
        return (it != end()) ? std::optional{it.move_value()} : std::nullopt;
    }

    const SnapshotPath& path() const { return reader_.path(); }

  private:
    const KVSegmentFileReader& reader_;
};

template <class TKVSegmentReader>
concept KVSegmentReaderConcept =
    std::same_as<TKVSegmentReader, KVSegmentReader<typename TKVSegmentReader::KeyDecoderType, typename TKVSegmentReader::ValueDecoderType>> ||
    std::derived_from<TKVSegmentReader, KVSegmentReader<typename TKVSegmentReader::KeyDecoderType, typename TKVSegmentReader::ValueDecoderType>>;

}  // namespace silkworm::snapshots
