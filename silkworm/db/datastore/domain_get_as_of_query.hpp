// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
        const snapshots::SnapshotRepositoryROAccess& repository_latest,
        const snapshots::SnapshotRepositoryROAccess& repository_historical,
        const snapshots::QueryCaches& query_caches)
        : query1_{*kvdb_entity.history, tx, repository_historical, query_caches},
          query2_{history_segment_names.front(), kvdb_entity, tx, repository_latest, query_caches} {}

    DomainGetAsOfQuery(
        const kvdb::DatabaseRef& database,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository_latest,
        const snapshots::SnapshotRepositoryROAccess& repository_historical,
        const snapshots::QueryCaches& query_caches)
        : query1_{database, tx, repository_historical, query_caches},
          query2_{history_segment_names.front(), database, tx, repository_latest, query_caches} {}

    using Key = decltype(TKeyEncoder1::value);
    using Value = decltype(TValueDecoder1::value);

    std::optional<Value> exec(const Key& key, std::optional<Timestamp> timestamp) {
        if (timestamp) {
            auto result1 = query1_.exec(key, *timestamp);
            if (result1) {
                return result1;
            }
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