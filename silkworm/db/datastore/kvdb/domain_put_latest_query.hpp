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

#include "../common/step.hpp"
#include "domain.hpp"
#include "domain_codecs.hpp"
#include "mdbx.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TKeyEncoder, EncoderConcept TValueEncoder>
struct DomainPutLatestQuery {
    RWTxn& tx;
    Domain entity;

    using TKey = decltype(TKeyEncoder::value);
    using TValue = decltype(TValueEncoder::value);

    void exec(const TKey& key, const TValue& value, Step step) {
        DomainKeyEncoder<TKeyEncoder> key_encoder{entity.has_large_values};
        key_encoder.value.key.value = key;
        key_encoder.value.timestamp.value = step;
        Slice key_data = key_encoder.encode();

        DomainValueEncoder<TValueEncoder> value_encoder{entity.has_large_values};
        value_encoder.value.value.value = value;
        value_encoder.value.timestamp.value = step;
        Slice value_data = value_encoder.encode();

        if (entity.values_table.value_mode == mdbx::value_mode::multi) {
            auto cursor = tx.rw_cursor_dup_sort(entity.values_table);

            // we need to erase an existing value with the same step if any
            // to find it, first encode a value with the same step and empty data
            DomainValueEncoder<RawEncoder<Bytes>> same_step_value_encoder{entity.has_large_values};
            same_step_value_encoder.value.timestamp.value = step;
            Slice same_step_value = same_step_value_encoder.encode();

            CursorResult result = cursor->find_multivalue(key_data, same_step_value, false);
            if (result) {
                // the found value will have the same key, but the step part can be different,
                // let's decode it ignoring the data part
                DomainValueDecoder<RawDecoder<ByteView>> existing_value_decoder{entity.has_large_values};
                existing_value_decoder.decode(result.value);
                Step existing_value_step = existing_value_decoder.value.timestamp.value;
                if (existing_value_step == step) {
                    cursor->erase();
                }
            }

            cursor->upsert(key_data, value_data);
        } else {
            tx.rw_cursor(entity.values_table)->upsert(key_data, value_data);
        }
    }
};

}  // namespace silkworm::datastore::kvdb
