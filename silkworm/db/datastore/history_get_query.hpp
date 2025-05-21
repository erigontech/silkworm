// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "kvdb/database.hpp"
#include "kvdb/history_get_query.hpp"
#include "snapshots/history_get_query.hpp"

namespace silkworm::datastore {

template <
    kvdb::EncoderConcept TKeyEncoder1, snapshots::EncoderConcept TKeyEncoder2,
    kvdb::DecoderConcept TValueDecoder1, snapshots::DecoderConcept TValueDecoder2,
    const snapshots::SegmentAndAccessorIndexNames& segment_names>
struct HistoryGetQuery {
    HistoryGetQuery(
        kvdb::History kvdb_entity,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository,
        const snapshots::QueryCaches& query_caches)
        : query1_{tx, kvdb_entity},
          query2_{repository, query_caches} {}

    HistoryGetQuery(
        const kvdb::DatabaseRef& database,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository,
        const snapshots::QueryCaches& query_caches)
        : HistoryGetQuery{
              database.domain(segment_names.front()).history.value(),
              tx,
              repository,
              query_caches,
          } {}

    using Key1 = decltype(TKeyEncoder1::value);
    using Key2 = decltype(TKeyEncoder2::value);
    static_assert(std::same_as<Key1, Key2>);
    using Key = Key1;

    using Value1 = decltype(TValueDecoder1::value);
    using Value2 = decltype(TValueDecoder2::value);
    static_assert(std::same_as<Value1, Value2>);
    using Value = Value1;

    std::optional<Value> exec(const Key& key, Timestamp timestamp) {
        auto result1 = query2_.exec(key, timestamp);
        if (result1) {
            return result1;
        }
        auto result2 = query1_.exec(key, timestamp);
        if (result2) {
            return std::move(*result2);
        }
        return std::nullopt;
    }

  private:
    kvdb::HistoryGetQuery<TKeyEncoder1, TValueDecoder1> query1_;
    snapshots::HistoryGetQuery<TKeyEncoder2, TValueDecoder2, segment_names> query2_;
};

}  // namespace silkworm::datastore