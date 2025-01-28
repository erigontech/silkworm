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
