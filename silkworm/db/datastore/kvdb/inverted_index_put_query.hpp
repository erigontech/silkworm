// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../common/timestamp.hpp"
#include "inverted_index.hpp"
#include "mdbx.hpp"
#include "timestamp_codec.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TKeyEncoder>
struct InvertedIndexPutQuery {
    RWTxn& tx;
    InvertedIndex entity;

    using Key = decltype(TKeyEncoder::value);

    void exec(const Key& key, const Timestamp timestamp, bool with_index_update) {
        return exec<TimestampEncoder>(key, timestamp, with_index_update);
    }

    template <EncoderConcept TTimestampEncoder, typename TTimestamp = decltype(TTimestampEncoder::value)>
    void exec(const Key& key, const TTimestamp& timestamp, bool with_index_update) {
        TKeyEncoder key_encoder;
        key_encoder.value = key;
        Slice key_slice = key_encoder.encode();

        TTimestampEncoder ts_encoder;
        ts_encoder.value = timestamp;
        Slice ts_slice = ts_encoder.encode();

        tx.rw_cursor(entity.keys_table)->upsert(ts_slice, key_slice);
        if (with_index_update) {
            tx.rw_cursor(entity.index_table)->upsert(key_slice, ts_slice);
        }
    }
};

}  // namespace silkworm::datastore::kvdb
