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

#include "domain_get_latest_query.hpp"
#include "history_get_query.hpp"

namespace silkworm::datastore {

template <
    kvdb::EncoderConcept TKeyEncoder1, snapshots::EncoderConcept TKeyEncoder2,
    kvdb::DecoderConcept TValueDecoder1, snapshots::DecoderConcept TValueDecoder2,
    const snapshots::SegmentAndAccessorIndexNames& history_segment_names>
struct DomainGetAsOfQuery {
    DomainGetAsOfQuery(
        kvdb::Domain kvdb_entity,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : query1_{*kvdb_entity.history, tx, repository},
          query2_{history_segment_names.front(), kvdb_entity, tx, repository} {}

    DomainGetAsOfQuery(
        const kvdb::DatabaseRef& database,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : query1_{database, tx, repository},
          query2_{history_segment_names.front(), database, tx, repository} {}

    using Key = decltype(TKeyEncoder1::value);
    using Value = decltype(TValueDecoder1::value);

    std::optional<Value> exec(const Key& key, Timestamp timestamp) {
        auto result1 = query1_.exec(key, timestamp);
        if (result1) {
            return result1;
        }
        auto result2 = query2_.exec(key);
        if (result2) {
            return std::move(result2->value);
        }
        return std::nullopt;
    }

  private:
    HistoryGetQuery<TKeyEncoder1, TKeyEncoder2, TValueDecoder1, TValueDecoder2, history_segment_names> query1_;
    DomainGetLatestQuery<TKeyEncoder1, TKeyEncoder2, TValueDecoder1, TValueDecoder2> query2_;
};

}  // namespace silkworm::datastore