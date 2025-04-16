// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "segment_reader.hpp"

#include <stdexcept>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::snapshots::segment {

SegmentFileReader::SegmentFileReader(
    SnapshotPath path,
    datastore::StepToTimestampConverter step_converter,
    std::optional<MemoryMappedRegion> segment_region,
    bool is_compressed)
    : path_(std::move(path)),
      step_converter_{std::move(step_converter)},
      decompressor_{
          path_.path(),
          segment_region,
          is_compressed ? seg::CompressionKind::kAll : seg::CompressionKind::kNone,
      } {
}

MemoryMappedRegion SegmentFileReader::memory_file_region() const {
    return decompressor_.memory_file().region();
}

SegmentFileReader::Iterator& SegmentFileReader::Iterator::operator++() {
    bool has_next = it_.has_next();
    ++it_;

    if (has_next) {
        if (path_) {
            decoder_->decode_word_with_metadata(*path_, step_converter_);
        }
        decoder_->decode_word(*it_);
        if (path_) {
            decoder_->check_sanity_with_metadata(*path_, step_converter_);
        }
    } else {
        decoder_.reset();
    }
    return *this;
}

SegmentFileReader::Iterator& SegmentFileReader::Iterator::operator+=(size_t count) {
    while ((count > 1) && it_.has_next()) {
        it_.skip();
        --count;
    }
    if (count > 0) {
        ++*this;
    }
    return *this;
}

bool operator==(const SegmentFileReader::Iterator& lhs, const SegmentFileReader::Iterator& rhs) {
    return (lhs.decoder_ == rhs.decoder_) &&
           (!lhs.decoder_ || (lhs.it_ == rhs.it_));
}

SegmentFileReader::Iterator SegmentFileReader::begin(std::shared_ptr<Decoder> decoder) const {
    auto it = decompressor_.begin();
    if (it == decompressor_.end()) {
        return end();
    }
    decoder->decode_word_with_metadata(path_, step_converter_);
    decoder->decode_word(*it);
    decoder->check_sanity_with_metadata(path_, step_converter_);
    return SegmentFileReader::Iterator{std::move(it), std::move(decoder), path(), step_converter_};
}

SegmentFileReader::Iterator SegmentFileReader::end() const {
    return SegmentFileReader::Iterator{decompressor_.end(), {}, path(), step_converter_};
}

SegmentFileReader::Iterator SegmentFileReader::seek(
    uint64_t offset,
    std::optional<ByteView> check_prefix,
    std::shared_ptr<Decoder> decoder) const {
    auto it = decompressor_.seek(offset, check_prefix.value_or(ByteView{}));
    if (it == decompressor_.end()) {
        return end();
    }
    decoder->decode_word_with_metadata(path_, step_converter_);
    try {
        decoder->decode_word(*it);
    } catch (...) {
        return end();
    }
    decoder->check_sanity_with_metadata(path_, step_converter_);
    return SegmentFileReader::Iterator{std::move(it), std::move(decoder), path(), step_converter_};
}

}  // namespace silkworm::snapshots::segment
