// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../common/codec.hpp"
#include "elias_fano_list.hpp"

namespace silkworm::snapshots::elias_fano {

struct EliasFanoDecoder : public snapshots::Decoder {
    EliasFanoList32 value{EliasFanoList32::empty_list()};

    ~EliasFanoDecoder() override = default;

    void decode_word(Word& word) override {
        if (word.holds_bytes()) {
            value = EliasFanoList32::from_encoded_data(std::get<Bytes>(std::move(word)));
        } else {
            value = EliasFanoList32::from_encoded_data(std::get<ByteView>(word));
        }
    }
};

static_assert(snapshots::DecoderConcept<EliasFanoDecoder>);

}  // namespace silkworm::snapshots::elias_fano
