// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/bytes.hpp>

#include "codec.hpp"

namespace silkworm::datastore::kvdb {

template <class TBytes>
concept BytesOrByteViewConcept = std::same_as<TBytes, Bytes> || std::same_as<TBytes, ByteView>;

template <BytesOrByteViewConcept TBytes>
struct RawDecoder : public Decoder {
    TBytes value;
    ~RawDecoder() override = default;
    void decode(Slice slice) override {
        value = from_slice(slice);
    }
};

static_assert(DecoderConcept<RawDecoder<Bytes>>);
static_assert(DecoderConcept<RawDecoder<ByteView>>);

template <BytesOrByteViewConcept TBytes>
struct RawEncoder : public Encoder {
    TBytes value;
    ~RawEncoder() override = default;
    Slice encode() override {
        return to_slice(ByteView{value});
    }
};

static_assert(EncoderConcept<RawEncoder<Bytes>>);
static_assert(EncoderConcept<RawEncoder<ByteView>>);

}  // namespace silkworm::datastore::kvdb
