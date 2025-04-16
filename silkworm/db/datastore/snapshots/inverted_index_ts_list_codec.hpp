// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../common/step_timestamp_converter.hpp"
#include "common/codec.hpp"
#include "common/snapshot_path.hpp"
#include "inverted_index_ts_list.hpp"

namespace silkworm::snapshots {

struct InvertedIndexTimestampListDecoder : public snapshots::Decoder {
    InvertedIndexTimestampList value;
    datastore::Timestamp base_timestamp{0};

    ~InvertedIndexTimestampListDecoder() override = default;
    void decode_word(Word& word) override;

    void decode_word_with_metadata(const SnapshotPath& path, const datastore::StepToTimestampConverter& step_converter) override {
        base_timestamp = step_converter.timestamp_from_step(path.step_range().start);
    }
};

}  // namespace silkworm::snapshots
