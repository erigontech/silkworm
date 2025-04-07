// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/common/ensure.hpp>

#include "codec.hpp"

namespace silkworm::snapshots {

template <class TBytes>
concept BytesOrByteViewConcept = std::same_as<TBytes, Bytes> || std::same_as<TBytes, ByteView> || std::same_as<TBytes, BytesOrByteView>;

template <BytesOrByteViewConcept TBytes>
struct RawDecoder : public Decoder {
    TBytes value;
    ~RawDecoder() override = default;
    void decode_word(Word& word) override {
        if (word.holds_bytes()) {
            if constexpr (std::same_as<TBytes, ByteView>) {
                ensure(false, "RawDecoder<ByteView> should be instead RawDecoder<Bytes>");
            }
            value = std::move(std::get<Bytes>(word));
        } else {
            value = std::get<ByteView>(word);
        }
    }
};

template <>
struct RawDecoder<BytesOrByteView> : public Decoder {
    BytesOrByteView value;
    ~RawDecoder() override = default;
    void decode_word(Word& word) override {
        value = std::move(word);
    }
};

static_assert(DecoderConcept<RawDecoder<Bytes>>);
static_assert(DecoderConcept<RawDecoder<ByteView>>);
static_assert(DecoderConcept<RawDecoder<BytesOrByteView>>);

template <BytesOrByteViewConcept TBytes>
struct RawEncoder : public Encoder {
    TBytes value;
    ~RawEncoder() override = default;
    ByteView encode_word() override {
        return value;
    }
};

static_assert(EncoderConcept<RawEncoder<Bytes>>);
static_assert(EncoderConcept<RawEncoder<ByteView>>);

}  // namespace silkworm::snapshots
