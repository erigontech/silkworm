// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "kv_segment_reader.hpp"

#include <array>

#include <silkworm/core/common/assert.hpp>

namespace silkworm::snapshots::segment {

KVSegmentFileReader::KVSegmentFileReader(
    SnapshotPath path,
    datastore::StepToTimestampConverter step_converter,
    seg::CompressionKind compression_kind,
    std::optional<MemoryMappedRegion> segment_region)
    : path_(std::move(path)),
      step_converter_{std::move(step_converter)},
      decompressor_{path_.path(), segment_region, compression_kind} {
}

MemoryMappedRegion KVSegmentFileReader::memory_file_region() const {
    return decompressor_.memory_file().region();
}

KVSegmentFileReader::Iterator& KVSegmentFileReader::Iterator::operator++() {
    for (auto& decoder : std::array{decoders_.first, decoders_.second}) {
        bool has_next = it_.has_next();

        if (decoder) {
            ++it_;
        } else {
            it_.skip();
        }

        if (has_next) {
            if (decoder) {
                if (path_) {
                    decoder->decode_word_with_metadata(*path_, step_converter_);
                }
                decoder->decode_word(*it_);
                if (path_) {
                    decoder->check_sanity_with_metadata(*path_, step_converter_);
                }
            }
        } else {
            decoders_.first.reset();
            decoders_.second.reset();
            break;
        }
    }
    return *this;
}

KVSegmentFileReader::Iterator& KVSegmentFileReader::Iterator::operator+=(size_t count) {
    count *= 2;
    while ((count > 2) && it_.has_next()) {
        it_.skip();
        --count;
    }
    if (count >= 2) {
        ++*this;
    }
    return *this;
}

bool operator==(const KVSegmentFileReader::Iterator& lhs, const KVSegmentFileReader::Iterator& rhs) {
    return (lhs.decoders_ == rhs.decoders_) &&
           ((!lhs.decoders_.first && !lhs.decoders_.second) || (lhs.it_ == rhs.it_));
}

KVSegmentFileReader::Iterator KVSegmentFileReader::begin(std::shared_ptr<Decoder> key_decoder, std::shared_ptr<Decoder> value_decoder) const {
    SILKWORM_ASSERT(key_decoder || value_decoder);
    auto it = decompressor_.begin();
    if (it == decompressor_.end()) {
        return end();
    }
    if (!it.has_next()) {
        return end();
    }

    if (key_decoder) {
        key_decoder->decode_word_with_metadata(path_, step_converter_);
        key_decoder->decode_word(*it);
        key_decoder->check_sanity_with_metadata(path_, step_converter_);
    }

    if (value_decoder) {
        ++it;
        value_decoder->decode_word_with_metadata(path_, step_converter_);
        value_decoder->decode_word(*it);
        value_decoder->check_sanity_with_metadata(path_, step_converter_);
    } else {
        it.skip();
    }

    return KVSegmentFileReader::Iterator{std::move(it), std::move(key_decoder), std::move(value_decoder), path(), step_converter_};
}

KVSegmentFileReader::Iterator KVSegmentFileReader::end() const {
    return KVSegmentFileReader::Iterator{decompressor_.end(), {}, {}, path(), step_converter_};
}

KVSegmentFileReader::Iterator KVSegmentFileReader::seek(
    uint64_t offset,
    std::optional<ByteView> check_prefix,
    std::shared_ptr<Decoder> key_decoder,
    std::shared_ptr<Decoder> value_decoder) const {
    SILKWORM_ASSERT(key_decoder || value_decoder);
    auto it = decompressor_.seek(offset, check_prefix.value_or(ByteView{}));
    if (it == decompressor_.end()) {
        return end();
    }
    if (!it.has_next()) {
        return end();
    }

    if (key_decoder) {
        key_decoder->decode_word_with_metadata(path_, step_converter_);
        try {
            key_decoder->decode_word(*it);
        } catch (...) {
            return end();
        }
        key_decoder->check_sanity_with_metadata(path_, step_converter_);
    }

    if (value_decoder) {
        ++it;
        value_decoder->decode_word_with_metadata(path_, step_converter_);
        value_decoder->decode_word(*it);
        value_decoder->check_sanity_with_metadata(path_, step_converter_);
    } else {
        it.skip();
    }

    return KVSegmentFileReader::Iterator{std::move(it), std::move(key_decoder), std::move(value_decoder), path(), step_converter_};
}

}  // namespace silkworm::snapshots::segment
