// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "kvdb/database.hpp"
#include "kvdb/domain_get_latest_query.hpp"
#include "snapshots/domain_get_latest_query.hpp"

namespace silkworm::datastore {

template <
    kvdb::EncoderConcept TKeyEncoder1, snapshots::EncoderConcept TKeyEncoder2,
    kvdb::DecoderConcept TValueDecoder1, snapshots::DecoderConcept TValueDecoder2>
struct DomainGetLatestQuery {
    DomainGetLatestQuery(
        datastore::EntityName entity_name,
        kvdb::Domain kvdb_entity,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository,
        const snapshots::QueryCaches& query_caches)
        : query1_{tx, kvdb_entity},
          query2_{repository, query_caches, entity_name} {}

    DomainGetLatestQuery(
        datastore::EntityName entity_name,
        const kvdb::DatabaseRef& database,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository,
        const snapshots::QueryCaches& query_caches)
        : DomainGetLatestQuery{
              entity_name,
              database.domain(entity_name),
              tx,
              repository,
              query_caches,
          } {}

    using Key1 = decltype(TKeyEncoder1::value);
    using Key2 = decltype(TKeyEncoder2::value);
    static_assert(std::same_as<Key1, Key2>);
    using Key = Key1;

    using Result1 = typename kvdb::DomainGetLatestQuery<TKeyEncoder1, TValueDecoder1>::Result;
    using Result2 = typename snapshots::DomainGetLatestQuery<TKeyEncoder2, TValueDecoder2>::Result;
    using Result = Result1;

    std::optional<Result> exec(const Key& key) {
        auto result1 = query1_.exec(key);
        if (result1) {
            return result1;
        }
        auto result2 = query2_.exec(key);
        if (result2) {
            return Result{std::move(result2->value), result2->step};
        }
        return std::nullopt;
    }

  private:
    kvdb::DomainGetLatestQuery<TKeyEncoder1, TValueDecoder1> query1_;
    snapshots::DomainGetLatestQuery<TKeyEncoder2, TValueDecoder2> query2_;
};

}  // namespace silkworm::datastore