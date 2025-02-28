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

    auto exec(const Key& key_start, const Key& key_end, std::optional<Timestamp> timestamp, bool ascending) {
        return silkworm::views::if_view(
            !timestamp.has_value(),
            query2_.exec(key_start, key_end, ascending),
            this->exec(key_start, key_end, timestamp.value_or(0), ascending));
    }

    auto exec(const Key& key_start, const Key& key_end, Timestamp timestamp, bool ascending) {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        return silkworm::views::merge_unique(
            query1_.exec(key_start, key_end, timestamp, ascending),
            query2_.exec(key_start, key_end, ascending),
            silkworm::views::MergeCompareFunc{},
            PairGetFirst<typename ResultItem::first_type, typename ResultItem::second_type>{},
            PairGetFirst<typename ResultItem::first_type, typename ResultItem::second_type>{});
    }

  private:
    HistoryRangeByKeysQuery<TKeyEncoder1, TKeyEncoder2, TKeyDecoder1, TKeyDecoder2, TValueDecoder1, TValueDecoder2> query1_;
    DomainRangeLatestQuery<TKeyEncoder1, TKeyEncoder2, TKeyDecoder1, TKeyDecoder2, TValueDecoder1, TValueDecoder2> query2_;
};

}  // namespace silkworm::datastore