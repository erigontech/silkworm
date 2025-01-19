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
        const snapshots::SnapshotRepositoryROAccess& repository)
        : query1_{tx, kvdb_entity},
          query2_{repository, entity_name} {}

    DomainGetLatestQuery(
        datastore::EntityName entity_name,
        const kvdb::DatabaseRef& database,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : DomainGetLatestQuery{
              entity_name,
              database.domain(entity_name),
              tx,
              repository,
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