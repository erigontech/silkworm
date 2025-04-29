// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/assert.hpp>

#include "common/ranges/if_view.hpp"
#include "common/ranges/merge_unique_view.hpp"
#include "domain_range_latest_query.hpp"
#include "history_range_by_keys_query.hpp"

namespace silkworm::datastore {

template <
    kvdb::EncoderConcept TKeyEncoder1, snapshots::EncoderConcept TKeyEncoder2,
    kvdb::DecoderConcept TKeyDecoder1, snapshots::DecoderConcept TKeyDecoder2,
    kvdb::DecoderConcept TValueDecoder1, snapshots::DecoderConcept TValueDecoder2>
struct DomainRangeAsOfQuery {
    DomainRangeAsOfQuery(
        datastore::EntityName entity_name,
        kvdb::Domain kvdb_entity,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository_latest,
        const snapshots::SnapshotRepositoryROAccess& repository_historical)
        : query1_{*kvdb_entity.history, tx, repository_historical},
          query2_{entity_name, kvdb_entity, tx, repository_latest} {}

    DomainRangeAsOfQuery(
        datastore::EntityName entity_name,
        const kvdb::DatabaseRef& database,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository_latest,
        const snapshots::SnapshotRepositoryROAccess& repository_historical)
        : query1_{entity_name, database, tx, repository_historical},
          query2_{entity_name, database, tx, repository_latest} {}

    using Key = decltype(TKeyEncoder1::value);
    using ResultItem = typename DomainRangeLatestQuery<TKeyEncoder1, TKeyEncoder2, TKeyDecoder1, TKeyDecoder2, TValueDecoder1, TValueDecoder2>::ResultItem;

    auto exec(const Key& key_start, const Key& key_end, std::optional<Timestamp> timestamp, bool ascending, bool skip_empty_values) {
        return silkworm::views::if_view(
            !timestamp.has_value(),
            query2_.exec(key_start, key_end, ascending),
            this->exec(key_start, key_end, timestamp.value_or(0), ascending, skip_empty_values));
    }

    auto exec(const Key& key_start, const Key& key_end, Timestamp timestamp, bool ascending, bool skip_empty_values) {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        auto skip_empty_value_predicate = [skip_empty_values](std::pair<Bytes, Bytes>& kv_pair) {
            if (!skip_empty_values) return true;
            return !kv_pair.second.empty();
        };

        return silkworm::views::merge_unique(
                   query1_.exec(key_start, key_end, timestamp, ascending),
                   query2_.exec(key_start, key_end, ascending),
                   silkworm::views::MergeCompareFunc{},
                   PairGetFirst<typename ResultItem::first_type, typename ResultItem::second_type>{},
                   PairGetFirst<typename ResultItem::first_type, typename ResultItem::second_type>{}) |
               std::views::filter(std::move(skip_empty_value_predicate));
    }

  private:
    HistoryRangeByKeysQuery<TKeyEncoder1, TKeyEncoder2, TKeyDecoder1, TKeyDecoder2, TValueDecoder1, TValueDecoder2> query1_;
    DomainRangeLatestQuery<TKeyEncoder1, TKeyEncoder2, TKeyDecoder1, TKeyDecoder2, TValueDecoder1, TValueDecoder2> query2_;
};

template <
    kvdb::EncoderConcept TKeyEncoder1, snapshots::EncoderConcept TKeyEncoder2,
    kvdb::DecoderConcept TKeyDecoder1, snapshots::DecoderConcept TKeyDecoder2,
    kvdb::DecoderConcept TValueDecoder1, snapshots::DecoderConcept TValueDecoder2>
using DomainRangeAsOfQueryResult = decltype(std::declval<DomainRangeAsOfQuery<TKeyEncoder1, TKeyEncoder2, TKeyDecoder1, TKeyDecoder2, TValueDecoder1, TValueDecoder2>>().exec(
    std::declval<const typename DomainRangeAsOfQuery<TKeyEncoder1, TKeyEncoder2, TKeyDecoder1, TKeyDecoder2, TValueDecoder1, TValueDecoder2>::Key&>(),
    std::declval<const typename DomainRangeAsOfQuery<TKeyEncoder1, TKeyEncoder2, TKeyDecoder1, TKeyDecoder2, TValueDecoder1, TValueDecoder2>::Key&>(),
    std::declval<std::optional<Timestamp>>(),
    std::declval<bool>(),
    std::declval<bool>()));

}  // namespace silkworm::datastore