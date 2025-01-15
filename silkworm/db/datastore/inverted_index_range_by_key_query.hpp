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

#include "concat_view.hpp"
#include "kvdb/database.hpp"
#include "kvdb/inverted_index_range_by_key_query.hpp"
#include "snapshots/inverted_index_range_by_key_query.hpp"

namespace silkworm::datastore {

template <kvdb::EncoderConcept TKeyEncoder1, snapshots::EncoderConcept TKeyEncoder2>
struct InvertedIndexRangeByKeyQuery {
    InvertedIndexRangeByKeyQuery(
        datastore::EntityName inverted_index_name,
        kvdb::InvertedIndex kvdb_inverted_index,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : query1_{tx, kvdb_inverted_index},
          query2_{repository, inverted_index_name} {}

    InvertedIndexRangeByKeyQuery(
        datastore::EntityName inverted_index_name,
        kvdb::DatabaseRef database,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : InvertedIndexRangeByKeyQuery{
              inverted_index_name,
              database.inverted_index(inverted_index_name),
              tx,
              repository,
          } {}

    using Key1 = decltype(TKeyEncoder1::value);
    using Key2 = decltype(TKeyEncoder2::value);
    static_assert(std::same_as<Key1, Key2>);
    using Key = Key1;

    template <bool ascending = true>
    auto exec(Key key, TimestampRange ts_range) {
        if constexpr (ascending) {
            return silkworm::views::concat(
                query2_.template exec<ascending>(key, ts_range),
                query1_.exec(key, ts_range, ascending));
        } else {
            return silkworm::views::concat(
                query1_.exec(key, ts_range, ascending),
                query2_.template exec<ascending>(key, ts_range));
        }
    }

  private:
    kvdb::InvertedIndexRangeByKeyQuery<TKeyEncoder1> query1_;
    snapshots::InvertedIndexRangeByKeyQuery<TKeyEncoder2> query2_;
};

}  // namespace silkworm::datastore
