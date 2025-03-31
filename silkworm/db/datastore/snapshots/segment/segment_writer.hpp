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

class SegmentFileWriter {
  public:
    class Iterator {
      public:
        using value_type = std::shared_ptr<Encoder>;
        using iterator_category [[maybe_unused]] = std::output_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = void;
        using reference = void;

        Iterator(
            seg::Compressor::Iterator it,
            std::shared_ptr<Encoder> encoder)
            : it_(it), encoder_(std::move(encoder)) {}

        Iterator& operator*() { return *this; }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++() {
            ++it_;
            return *this;
        }

        Iterator& operator=(const value_type& value);

        std::shared_ptr<Encoder> encoder() const { return encoder_; }

      private:
        seg::Compressor::Iterator it_;
        std::shared_ptr<Encoder> encoder_;
    };

    static_assert(std::output_iterator<Iterator, typename Iterator::value_type>);

    explicit SegmentFileWriter(
        SnapshotPath path,
        const std::filesystem::path& tmp_dir_path,
        bool is_compressed = true);

    SegmentFileWriter(SegmentFileWriter&&) = default;
    SegmentFileWriter& operator=(SegmentFileWriter&&) = default;

    SnapshotPath path() const { return path_; }

    Iterator out(std::shared_ptr<Encoder> encoder);

    static void flush(SegmentFileWriter writer);

  private:
    SnapshotPath path_;
    seg::Compressor compressor_;
};

template <EncoderConcept TEncoder>
class SegmentWriter {
  public:
    class Iterator {
      public:
        using value_type = decltype(TEncoder::value);
        using iterator_category [[maybe_unused]] = std::output_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = void;
        using reference = void;

        explicit Iterator(SegmentFileWriter::Iterator it)
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
        SegmentFileWriter::Iterator::value_type set_value(value_type value) {
            Encoder& base_encoder = *it_.encoder();
            // dynamic_cast is safe because TEncoder was used when creating the Iterator
            auto& encoder = dynamic_cast<TEncoder&>(base_encoder);
            encoder.value = std::move(value);
            return it_.encoder();
        }

        SegmentFileWriter::Iterator it_;
    };

    static_assert(std::output_iterator<Iterator, typename Iterator::value_type>);

    using EncoderType = TEncoder;

    explicit SegmentWriter(SegmentFileWriter& writer) : writer_(writer) {}

    Iterator out() {
        return Iterator{writer_.out(std::make_shared<TEncoder>())};
    }

  private:
    SegmentFileWriter& writer_;
};

template <class TSegmentWriter>
concept SegmentWriterConcept =
    std::same_as<TSegmentWriter, SegmentWriter<typename TSegmentWriter::EncoderType>> ||
    std::derived_from<TSegmentWriter, SegmentWriter<typename TSegmentWriter::EncoderType>>;

}  // namespace silkworm::snapshots::segment
