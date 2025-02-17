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

#include "kv_segment_reader.hpp"

#include <array>
#include <stdexcept>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::snapshots::segment {

KVSegmentFileReader::KVSegmentFileReader(
    SnapshotPath path,
    seg::CompressionKind compression_kind,
    std::optional<MemoryMappedRegion> segment_region)
    : path_(std::move(path)),
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
                decoder->decode_word(*it_);
                if (path_) {
                    decoder->check_sanity_with_metadata(*path_);
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
        key_decoder->decode_word(*it);
        key_decoder->check_sanity_with_metadata(path_);
    }

    if (value_decoder) {
        ++it;
        value_decoder->decode_word(*it);
        value_decoder->check_sanity_with_metadata(path_);
    } else {
        it.skip();
    }

    return KVSegmentFileReader::Iterator{std::move(it), std::move(key_decoder), std::move(value_decoder), path()};
}

KVSegmentFileReader::Iterator KVSegmentFileReader::end() const {
    return KVSegmentFileReader::Iterator{decompressor_.end(), {}, {}, path()};
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
        try {
            key_decoder->decode_word(*it);
        } catch (...) {
            return end();
        }
        key_decoder->check_sanity_with_metadata(path_);
    }

    if (value_decoder) {
        ++it;
        value_decoder->decode_word(*it);
        value_decoder->check_sanity_with_metadata(path_);
    } else {
        it.skip();
    }

    return KVSegmentFileReader::Iterator{std::move(it), std::move(key_decoder), std::move(value_decoder), path()};
}

}  // namespace silkworm::snapshots::segment
