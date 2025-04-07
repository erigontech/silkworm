// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/endian.hpp>

#include "../common/timestamp.hpp"
#include "common/codec.hpp"
#include "common/raw_codec.hpp"

namespace silkworm::snapshots {

template <EncoderConcept TIIKeyEncoder>
struct HistoryAccessorIndexKeyEncoder : public snapshots::Encoder {
    struct Value {
        datastore::Timestamp timestamp{0};
        decltype(TIIKeyEncoder::value) inverted_index_key;
    } value;

    Bytes word;
    TIIKeyEncoder inverted_index_key_encoder;

    ~HistoryAccessorIndexKeyEncoder() override = default;

    ByteView encode_word() override {
        word.clear();

        word.append(sizeof(datastore::Timestamp), 0);
        endian::store_big_u64(word.data(), value.timestamp);

        inverted_index_key_encoder.value = std::move(value.inverted_index_key);
        word += inverted_index_key_encoder.encode_word();

        return word;
    }
};

static_assert(snapshots::EncoderConcept<HistoryAccessorIndexKeyEncoder<RawEncoder<ByteView>>>);

}  // namespace silkworm::snapshots
