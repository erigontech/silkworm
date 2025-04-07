// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <concepts>
#include <filesystem>
#include <iterator>
#include <memory>
#include <utility>

#include "../common/codec.hpp"
#include "../common/snapshot_path.hpp"
#include "seg/compressor.hpp"

namespace silkworm::snapshots::segment {

class KVSegmentFileWriter {
  public:
    class Iterator {
      public:
        using value_type = std::pair<std::shared_ptr<Encoder>, std::shared_ptr<Encoder>>;
        using iterator_category [[maybe_unused]] = std::output_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = void;
        using reference = void;

        Iterator(
            seg::Compressor::Iterator it,
            std::shared_ptr<Encoder> key_encoder,
            std::shared_ptr<Encoder> value_encoder)
            : it_{it},
              encoders_{std::move(key_encoder), std::move(value_encoder)} {}

        Iterator& operator*() { return *this; }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++() { /* noop */
            return *this;
        }

        Iterator& operator=(const value_type& value);

        std::shared_ptr<Encoder> key_encoder() const { return encoders_.first; }
        std::shared_ptr<Encoder> value_encoder() const { return encoders_.second; }

      private:
        seg::Compressor::Iterator it_;
        value_type encoders_;
    };

    static_assert(std::output_iterator<Iterator, typename Iterator::value_type>);

    KVSegmentFileWriter(
        SnapshotPath path,
        seg::CompressionKind compression_kind,
        const std::filesystem::path& tmp_dir_path);

    KVSegmentFileWriter(KVSegmentFileWriter&&) = default;
    KVSegmentFileWriter& operator=(KVSegmentFileWriter&&) = default;

    SnapshotPath path() const { return path_; }

    Iterator out(
        std::shared_ptr<Encoder> key_encoder,
        std::shared_ptr<Encoder> value_encoder);

    static void flush(KVSegmentFileWriter writer);

  private:
    SnapshotPath path_;
    seg::Compressor compressor_;
};

template <EncoderConcept TKeyEncoder, EncoderConcept TValueEncoder>
class KVSegmentWriter {
  public:
    class Iterator {
      public:
        using value_type = std::pair<decltype(TKeyEncoder::value), decltype(TValueEncoder::value)>;
        using iterator_category [[maybe_unused]] = std::output_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = void;
        using reference = void;

        explicit Iterator(KVSegmentFileWriter::Iterator it)
            : it_(std::move(it)) {}

        Iterator& operator*() { return *this; }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++() {
            ++it_;
            return *this;
        }

        Iterator& operator=(value_type value) {
            *it_ = set_value(std::move(value));
            return *this;
        }

      private:
        KVSegmentFileWriter::Iterator::value_type set_value(value_type value) {
            Encoder& base_key_encoder = *it_.key_encoder();
            Encoder& base_value_encoder = *it_.value_encoder();
            // dynamic_cast is safe because TKeyEncoder was used when creating the Iterator
            auto& key_encoder = dynamic_cast<TKeyEncoder&>(base_key_encoder);
            key_encoder.value = std::move(value.first);
            // dynamic_cast is safe because TValueEncoder was used when creating the Iterator
            auto& value_encoder = dynamic_cast<TValueEncoder&>(base_value_encoder);
            value_encoder.value = std::move(value.second);
            return {it_.key_encoder(), it_.value_encoder()};
        }

        KVSegmentFileWriter::Iterator it_;
    };

    static_assert(std::output_iterator<Iterator, typename Iterator::value_type>);

    using KeyEncoderType = TKeyEncoder;
    using ValueEncoderType = TValueEncoder;

    explicit KVSegmentWriter(KVSegmentFileWriter& writer) : writer_(writer) {}

    Iterator out() {
        return Iterator{writer_.out(std::make_shared<TKeyEncoder>(), std::make_shared<TValueEncoder>())};
    }

  private:
    KVSegmentFileWriter& writer_;
};

template <class TKVSegmentWriter>
concept KVSegmentWriterConcept =
    std::same_as<TKVSegmentWriter, KVSegmentWriter<typename TKVSegmentWriter::KeyEncoderType, typename TKVSegmentWriter::ValueEncoderType>> ||
    std::derived_from<TKVSegmentWriter, KVSegmentWriter<typename TKVSegmentWriter::KeyEncoderType, typename TKVSegmentWriter::ValueEncoderType>>;

}  // namespace silkworm::snapshots::segment
