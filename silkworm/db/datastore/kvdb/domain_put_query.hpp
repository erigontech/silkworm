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

#include "domain_put_latest_query.hpp"
#include "history_delete_query.hpp"
#include "history_put_query.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TKeyEncoder, EncoderConcept TValueEncoder>
struct DomainPutQuery {
    RWTxn& tx;
    Domain entity;

    using Key = decltype(TKeyEncoder::value);
    using Value = decltype(TValueEncoder::value);

    void exec(
        const Key& key,
        const Value& value,
        Timestamp timestamp,
        const std::optional<Value>& prev_value) {

        DomainPutLatestQuery<TKeyEncoder, TValueEncoder> value_query{tx, entity};
        value_query.exec(key, value, Step::from_txn_id(timestamp));


        if (entity.history) {
            if (prev_value) {
                HistoryPutQuery<TKeyEncoder, TValueEncoder> history_query{tx, *entity.history};
                history_query.exec(key, *prev_value, timestamp);
            } else {
                HistoryDeleteQuery<TKeyEncoder> history_query{tx, *entity.history};
                history_query.exec(key, timestamp);
            }
        }
    }
};

}  // namespace silkworm::datastore::kvdb
