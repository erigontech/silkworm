// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "inverted_index_ts_list_codec.hpp"

namespace silkworm::snapshots {

static_assert(snapshots::DecoderConcept<InvertedIndexTimestampListDecoder>);

static constexpr uint8_t kNonV1EncodingMask = 0b10000000;
static constexpr uint8_t kSimpleEncodingSizeMask = 0b00001111;
static constexpr uint8_t kSimpleEncodingMaxByte = 0b10001111;

void InvertedIndexTimestampListDecoder::decode_word(Word& word) {
    ByteView data{word};
    if (data.empty()) {
        value = {};
    } else if ((data[0] & kNonV1EncodingMask) == 0) {
        auto list = elias_fano::EliasFanoList32::from_encoded_data(std::move(word));
        value = InvertedIndexTimestampList{std::move(list)};
    } else if ((data[0] | kSimpleEncodingSizeMask) == kSimpleEncodingMaxByte) {
        value = InvertedIndexTimestampList{
            std::move(word),
            base_timestamp,
            1,
            static_cast<size_t>(data[0] & kSimpleEncodingSizeMask) + 1,
        };
    } else {
        throw std::runtime_error{"InvertedIndexTimestampListDecoder: unsupported encoding"};
    }
}

}  // namespace silkworm::snapshots
