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

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace silkworm::snapshots {

class SnapshotPath;

struct Encoder {
    virtual ~Encoder() = default;
    virtual ByteView encode_word() = 0;
};

template <class TEncoder>
concept EncoderConcept =
    std::derived_from<TEncoder, Encoder> &&
    requires(TEncoder encoder) { encoder.value; };

struct Decoder {
    virtual ~Decoder() = default;
    virtual void decode_word(BytesOrByteView& word) = 0;  // this allows word to be moved after decoding
    virtual void check_sanity_with_metadata(const SnapshotPath& /*path*/) {}
};

template <class TDecoder>
concept DecoderConcept =
    std::derived_from<TDecoder, Decoder> &&
    requires(TDecoder decoder) { decoder.value; };

struct Codec : public Encoder, public Decoder {
    ~Codec() override = default;
};

}  // namespace silkworm::snapshots
