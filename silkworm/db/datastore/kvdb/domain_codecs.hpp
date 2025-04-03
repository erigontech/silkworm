// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../common/step.hpp"
#include "big_endian_codec.hpp"
#include "kvts_codec.hpp"

namespace silkworm::datastore::kvdb {

struct InvertedStepCodec : public Codec {
    Step value{0};
    BigEndianU64Codec codec;
    static constexpr size_t kEncodedSize = sizeof(decltype(BigEndianU64Codec::value));

    ~InvertedStepCodec() override = default;

    Slice encode() override {
        codec.value = ~value.value;
        return codec.encode();
    }

    void decode(Slice slice) override {
        codec.decode(slice);
        value = Step(~codec.value);
    }
};

static_assert(EncoderConcept<InvertedStepCodec>);
static_assert(DecoderConcept<InvertedStepCodec>);

template <EncoderConcept TEncoder>
using DomainKeyEncoder = KVTSKeyEncoder<TEncoder, InvertedStepCodec>;

template <EncoderConcept TEncoder>
using DomainValueEncoder = KVTSValueEncoder<TEncoder, InvertedStepCodec>;

template <DecoderConcept TDecoder>
using DomainKeyDecoder = KVTSKeyDecoder<TDecoder, InvertedStepCodec, InvertedStepCodec::kEncodedSize>;

template <DecoderConcept TDecoder>
using DomainValueDecoder = KVTSValueDecoder<TDecoder, InvertedStepCodec, InvertedStepCodec::kEncodedSize>;

}  // namespace silkworm::datastore::kvdb
