// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>

#include <silkworm/core/types/hash.hpp>
#include <silkworm/db/datastore/snapshots/common/codec.hpp>

namespace silkworm::db::state {

struct HashSnapshotsDecoder : public snapshots::Decoder {
    Hash value;

    ~HashSnapshotsDecoder() override = default;

    void decode_word(Word& word) override {
        const ByteView word_view = word;
        if (word_view.size() < kHashLength)
            throw std::runtime_error{"HashSnapshotsDecoder failed to decode"};
        value = Hash{word_view};
    }
};

static_assert(snapshots::DecoderConcept<HashSnapshotsDecoder>);

}  // namespace silkworm::db::state
