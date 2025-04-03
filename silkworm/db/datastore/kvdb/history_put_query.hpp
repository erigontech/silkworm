// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../common/timestamp.hpp"
#include "history.hpp"
#include "history_codecs.hpp"
#include "inverted_index_put_query.hpp"
#include "mdbx.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TKeyEncoder, EncoderConcept TValueEncoder>
struct HistoryPutQuery {
    RWTxn& tx;
    History entity;

    using Key = decltype(TKeyEncoder::value);
    using Value = decltype(TValueEncoder::value);

    void exec(const Key& key, const Value& value, Timestamp timestamp) {
        HistoryKeyEncoder<TKeyEncoder> key_encoder{entity.has_large_values};
        key_encoder.value.key.value = key;
        key_encoder.value.timestamp.value = timestamp;
        Slice key_data = key_encoder.encode();

        HistoryValueEncoder<TValueEncoder> value_encoder{entity.has_large_values};
        value_encoder.value.value.value = value;
        value_encoder.value.timestamp.value = timestamp;
        Slice value_data = value_encoder.encode();

        tx.rw_cursor(entity.values_table)->upsert(key_data, value_data);

        InvertedIndexPutQuery<TKeyEncoder> inverted_index_query{tx, entity.inverted_index};
        inverted_index_query.exec(key, timestamp, false);
    }
};

}  // namespace silkworm::datastore::kvdb
