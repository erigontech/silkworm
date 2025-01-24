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

    using Key = decltype(TKeyEncoder::value);
    using Value = decltype(TValueEncoder::value);

    void exec(const Key& key, const Value& value, Step step) {
        DomainKeyEncoder<TKeyEncoder> key_encoder{entity.has_large_values};
        key_encoder.value.key.value = key;
        key_encoder.value.timestamp.value = step;
        Slice key_data = key_encoder.encode();

        DomainValueEncoder<TValueEncoder> value_encoder{entity.has_large_values};
        value_encoder.value.value.value = value;
        value_encoder.value.timestamp.value = step;
        Slice value_data = value_encoder.encode();

        SILK_DEBUG << "Putting  " << entity.values_table.name << " with key " << to_hex(datastore::kvdb::from_slice(key_data), true) << " value " << to_hex(datastore::kvdb::from_slice(value_data), true);

        if (entity.values_table.value_mode == mdbx::value_mode::multi) {
            auto cursor = tx.rw_cursor_dup_sort(entity.values_table);

            // we need to erase an existing value with the same step if any
            // to find it, first encode a value with the same step and empty data
            DomainValueEncoder<RawEncoder<Bytes>> same_step_value_encoder{entity.has_large_values};
            same_step_value_encoder.value.timestamp.value = step;
            Slice same_step_value = same_step_value_encoder.encode();

            SILK_DEBUG << "DupSort looking for existing value " << to_hex(datastore::kvdb::from_slice(same_step_value), true);

            CursorResult result = cursor->lower_bound_multivalue(key_data, same_step_value, false);
            if (result) {
                SILK_DEBUG << " found and ";
                // the found value will have the same key, but the step part can be different,
                // let's decode it ignoring the data part
                DomainValueDecoder<RawDecoder<ByteView>> existing_value_decoder{entity.has_large_values};
                existing_value_decoder.decode(result.value);
                Step existing_value_step = existing_value_decoder.value.timestamp.value;
                if (existing_value_step == step) {
                    cursor->erase();
                    SILK_DEBUG << "earasing";
                } else {
                    SILK_DEBUG << "not earasing, existing_value_step: " << existing_value_step.to_string();
                }
            } else {
                SILK_DEBUG << " not found";
            }

            cursor->upsert(key_data, value_data);
        } else {
            tx.rw_cursor(entity.values_table)->upsert(key_data, value_data);
        }
    }
};

}  // namespace silkworm::datastore::kvdb
