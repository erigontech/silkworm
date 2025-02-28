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

#include "codec.hpp"

namespace silkworm::snapshots {

template <class TBytes>
concept BytesOrByteViewConcept = std::same_as<TBytes, Bytes> || std::same_as<TBytes, ByteView>;

template <BytesOrByteViewConcept TBytes>
struct RawDecoder : public Decoder {
    TBytes value;
    ~RawDecoder() override = default;
    void decode_word(BytesOrByteView& word) override {
        if (word.holds_bytes()) {
            value = std::move(std::get<Bytes>(word));  // TODO(canepat) BytesOrByteView vs TBytes
        } else {
            value = std::get<ByteView>(word);
        }
    }
};

static_assert(DecoderConcept<RawDecoder<Bytes>>);
static_assert(DecoderConcept<RawDecoder<ByteView>>);

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
