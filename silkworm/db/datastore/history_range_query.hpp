/*
   Copyright 2025 The Silkworm Authors

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

#include <algorithm>
#include <functional>
#include <utility>

#include "kvdb/database.hpp"
#include "kvdb/history_range_query.hpp"
#include "merge_view.hpp"
#include "snapshots/history_range_query.hpp"

namespace silkworm::datastore {

template <
    kvdb::DecoderConcept TKeyDecoder1, snapshots::DecoderConcept TKeyDecoder2,
    kvdb::DecoderConcept TValueDecoder1, snapshots::DecoderConcept TValueDecoder2>
struct HistoryRangeQuery {
    HistoryRangeQuery(
        datastore::EntityName entity_name,
        kvdb::History kvdb_entity,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : query1_{tx, kvdb_entity},
          query2_{repository, entity_name} {}

    HistoryRangeQuery(
        datastore::EntityName entity_name,
        const kvdb::DatabaseRef& database,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : HistoryRangeQuery{
              entity_name,
              database.domain(entity_name).history.value(),
              tx,
              repository,
          } {}

    using Key = decltype(TKeyDecoder1::value);
    using Value = decltype(TValueDecoder1::value);
    using ResultItem = std::pair<Key, Value>;

    template <typename T1, typename T2>
    struct PairGetFirst {
        constexpr const T1& operator()(const std::pair<T1, T2>& p) const noexcept {
            return p.first;
        }
    };

    auto exec(TimestampRange ts_range, bool ascending) {
        SILKWORM_ASSERT(ascending);  // descending is not implemented
        return silkworm::views::merge(
            query1_.exec(ts_range, ascending),
            query2_.exec(ts_range, ascending),
            std::less{},
            PairGetFirst<Key, Value>{},
            PairGetFirst<Key, Value>{});
    }

  private:
    kvdb::HistoryRangeQuery<TKeyDecoder1, TValueDecoder1> query1_;
    snapshots::HistoryRangeQuery<TKeyDecoder2, TValueDecoder2> query2_;
};

}  // namespace silkworm::datastore
