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

#include <silkworm/core/common/assert.hpp>

#include "kvdb/codec.hpp"
#include "kvdb/database.hpp"
#include "snapshots/domain_range_latest_query.hpp"
// #include "kvdb/domain_range_latest_query.hpp"

namespace silkworm::datastore {

template <
    kvdb::EncoderConcept TKeyEncoder1, snapshots::EncoderConcept TKeyEncoder2,
    kvdb::DecoderConcept TKeyDecoder1, snapshots::DecoderConcept TKeyDecoder2,
    kvdb::DecoderConcept TValueDecoder1, snapshots::DecoderConcept TValueDecoder2>
struct DomainRangeLatestQuery {
    DomainRangeLatestQuery(
        datastore::EntityName entity_name,
        kvdb::Domain /*kvdb_entity*/,
        kvdb::ROTxn& /*tx*/,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : /*query1_{tx, kvdb_entity},*/
          query2_{repository, entity_name} {}

    DomainRangeLatestQuery(
        datastore::EntityName entity_name,
        const kvdb::DatabaseRef& database,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : DomainRangeLatestQuery{
              entity_name,
              database.domain(entity_name),
              tx,
              repository,
          } {}

    using Key1 = decltype(TKeyEncoder1::value);
    using Key2 = decltype(TKeyEncoder2::value);
    static_assert(std::same_as<Key1, Key2>);
    using Key = Key1;

    // using ResultItem1 = typename kvdb::DomainRangeLatestQuery<TKeyEncoder1, TKeyDecoder1, TValueDecoder1>::ResultItem;
    using ResultItem2 = typename snapshots::DomainRangeLatestQuery<TKeyEncoder2, TKeyDecoder2, TValueDecoder2>::ResultItem;
    using ResultItem = ResultItem2;

    auto exec(const Key& key_start, const Key& key_end, bool ascending) {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        // TODO: merge unique with kvdb query1_
        return query2_.exec(key_start, key_end, ascending);
    }

  private:
    // kvdb::DomainRangeLatestQuery<TKeyEncoder1, TKeyDecoder1, TValueDecoder1> query1_;
    snapshots::DomainRangeLatestQuery<TKeyEncoder2, TKeyDecoder2, TValueDecoder2> query2_;
};

}  // namespace silkworm::datastore