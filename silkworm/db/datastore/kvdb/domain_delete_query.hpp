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

#include "domain_put_query.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TKeyEncoder, EncoderConcept TValueEncoder>
struct DomainDeleteQuery {
    RWTxn& tx;
    Domain entity;

    using Key = decltype(TKeyEncoder::value);
    using Value = decltype(TValueEncoder::value);

    void exec(
        const Key& key,
        Timestamp timestamp,
        const std::optional<Value>& prev_value,
        Step prev_step) {
        if (prev_value) {
            DomainPutQuery<TKeyEncoder, RawEncoder<ByteView>> query{tx, entity};
            query.exec(key, ByteView{}, timestamp, prev_value, prev_step);
        }
    }
};

}  // namespace silkworm::datastore::kvdb
