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

#include "history_put_query.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TKeyEncoder>
struct HistoryDeleteQuery {
    RWTxn& tx;
    History entity;

    using Key = decltype(TKeyEncoder::value);

    void exec(const Key& key, Timestamp timestamp) {
        HistoryPutQuery<TKeyEncoder, RawEncoder<ByteView>> query{tx, entity};
        query.exec(key, ByteView{}, timestamp);
    }
};

}  // namespace silkworm::datastore::kvdb
