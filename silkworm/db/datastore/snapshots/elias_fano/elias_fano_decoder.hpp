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

#include <optional>

#include "../common/codec.hpp"
#include "elias_fano_list.hpp"

namespace silkworm::snapshots::elias_fano {

struct EliasFanoDecoder : public snapshots::Decoder {
    EliasFanoList32 value{EliasFanoList32::empty_list()};

    ~EliasFanoDecoder() override = default;

    void decode_word(ByteView word) override {
        value = EliasFanoList32::from_encoded_data(std::span<const uint8_t>{word.data(), word.size()});
    }
};

static_assert(snapshots::DecoderConcept<EliasFanoDecoder>);

}  // namespace silkworm::snapshots::elias_fano
