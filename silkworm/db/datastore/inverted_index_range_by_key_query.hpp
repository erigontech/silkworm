// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "common/ranges/concat_view.hpp"
#include "common/ranges/if_view.hpp"
#include "kvdb/database.hpp"
#include "kvdb/inverted_index_range_by_key_query.hpp"
#include "snapshots/inverted_index_range_by_key_query.hpp"

namespace silkworm::datastore {

template <kvdb::EncoderConcept TKeyEncoder1, snapshots::EncoderConcept TKeyEncoder2>
struct InvertedIndexRangeByKeyQuery {
    InvertedIndexRangeByKeyQuery(
        datastore::EntityName entity_name,
        kvdb::InvertedIndex kvdb_entity,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : query1_{tx, kvdb_entity},
          query2_{repository, entity_name} {}

    InvertedIndexRangeByKeyQuery(
        datastore::EntityName entity_name,
        const kvdb::DatabaseRef& database,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : InvertedIndexRangeByKeyQuery{
              entity_name,
              database.inverted_index(entity_name),
              tx,
              repository,
          } {}

    using Key1 = decltype(TKeyEncoder1::value);
    using Key2 = decltype(TKeyEncoder2::value);
    static_assert(std::same_as<Key1, Key2>);
    using Key = Key1;

    auto exec(Key key, TimestampRange ts_range, bool ascending) {
        return silkworm::views::if_view(
            ascending,
            silkworm::views::concat(
                query2_.exec(key, ts_range, ascending),
                query1_.exec(key, ts_range, ascending)),
            silkworm::views::concat(
                query1_.exec(key, ts_range, ascending),
                query2_.exec(key, ts_range, ascending)));
    }

  private:
    kvdb::InvertedIndexRangeByKeyQuery<TKeyEncoder1> query1_;
    snapshots::InvertedIndexRangeByKeyQuery<TKeyEncoder2> query2_;
};

}  // namespace silkworm::datastore
