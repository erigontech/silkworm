// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <functional>
#include <utility>

#include "common/pair_get.hpp"
#include "common/ranges/merge_view.hpp"
#include "kvdb/database.hpp"
#include "kvdb/history_range_in_period_query.hpp"
#include "snapshots/history_range_in_period_query.hpp"

namespace silkworm::datastore {

template <
    kvdb::DecoderConcept TKeyDecoder1, snapshots::DecoderConcept TKeyDecoder2,
    kvdb::DecoderConcept TValueDecoder1, snapshots::DecoderConcept TValueDecoder2>
struct HistoryRangeInPeriodQuery {
    HistoryRangeInPeriodQuery(
        datastore::EntityName entity_name,
        kvdb::History kvdb_entity,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : query1_{tx, kvdb_entity},
          query2_{repository, entity_name} {}

    HistoryRangeInPeriodQuery(
        datastore::EntityName entity_name,
        const kvdb::DatabaseRef& database,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : HistoryRangeInPeriodQuery{
              entity_name,
              database.domain(entity_name).history.value(),
              tx,
              repository,
          } {}

    using Key = decltype(TKeyDecoder1::value);
    using Value = decltype(TValueDecoder1::value);
    using ResultItem = std::pair<Key, Value>;

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
    kvdb::HistoryRangeInPeriodQuery<TKeyDecoder1, TValueDecoder1> query1_;
    snapshots::HistoryRangeInPeriodQuery<TKeyDecoder2, TValueDecoder2> query2_;
};

}  // namespace silkworm::datastore
