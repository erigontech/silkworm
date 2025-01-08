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

#include "../common/timestamp.hpp"
#include "history.hpp"
#include "inverted_index_put_query.hpp"
#include "kvts_codec.hpp"
#include "mdbx.hpp"
#include "timestamp_codec.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TEncoder>
using HistoryKeyEncoder = KVTSKeyEncoder<TEncoder, TimestampEncoder>;

template <EncoderConcept TEncoder>
using HistoryValueEncoder = KVTSValueEncoder<TEncoder, TimestampEncoder>;

template <EncoderConcept TKeyEncoder, EncoderConcept TValueEncoder>
struct HistoryPutQuery {
    RWTxn& tx;
    History entity;

    using TKey = decltype(TKeyEncoder::value);
    using TValue = decltype(TValueEncoder::value);

    void exec(const TKey& key, const TValue& value, Timestamp timestamp) {
        HistoryKeyEncoder<TKeyEncoder> key_encoder{entity.has_large_values};
        key_encoder.value.key.value = key;
        key_encoder.value.timestamp.value = timestamp;

        HistoryValueEncoder<TValueEncoder> value_encoder{entity.has_large_values};
        value_encoder.value.value.value = value;
        value_encoder.value.timestamp.value = timestamp;

        tx.rw_cursor(entity.values_table)->insert(key_encoder.encode(), value_encoder.encode());

        InvertedIndexPutQuery<TKeyEncoder> inverted_index_query{tx, entity.inverted_index};
        inverted_index_query.exec(key, timestamp, false);
    }
};

}  // namespace silkworm::datastore::kvdb
