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
