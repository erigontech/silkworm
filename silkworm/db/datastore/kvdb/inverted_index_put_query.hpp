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
#include "inverted_index.hpp"
#include "mdbx.hpp"
#include "timestamp_codec.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TKeyEncoder>
struct InvertedIndexPutQuery {
    RWTxn& tx;
    InvertedIndex entity;

    using TKey = decltype(TKeyEncoder::value);

    void exec(const TKey& key, const Timestamp timestamp, bool with_index_update) {
        return exec<TimestampEncoder>(key, timestamp, with_index_update);
    }

    template <EncoderConcept TTimestampEncoder, typename TTimestamp = decltype(TTimestampEncoder::value)>
    void exec(const TKey& key, const TTimestamp& timestamp, bool with_index_update) {
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
