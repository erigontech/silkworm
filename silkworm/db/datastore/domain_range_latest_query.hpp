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

#include "common/pair_get.hpp"
#include "common/ranges/merge_unique_view.hpp"
#include "kvdb/database.hpp"
#include "kvdb/domain_range_latest_query.hpp"
#include "kvdb/raw_codec.hpp"
#include "snapshots/common/raw_codec.hpp"
#include "snapshots/domain_range_latest_query.hpp"

namespace silkworm::datastore {

template <
    kvdb::EncoderConcept TKeyEncoder1, snapshots::EncoderConcept TKeyEncoder2,
    kvdb::DecoderConcept TKeyDecoder1, snapshots::DecoderConcept TKeyDecoder2,
    kvdb::DecoderConcept TValueDecoder1, snapshots::DecoderConcept TValueDecoder2>
struct DomainRangeLatestQuery {
    DomainRangeLatestQuery(
        datastore::EntityName entity_name,
        kvdb::Domain kvdb_entity,
        kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : query1_{tx, std::move(kvdb_entity)},
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

    using ResultItemKey1 = decltype(TKeyDecoder1::value);
    using ResultItemKey2 = decltype(TKeyDecoder2::value);
    static_assert(std::same_as<ResultItemKey1, ResultItemKey2>);
    using ResultItemKey = ResultItemKey1;

    using ResultItemValue1 = decltype(TValueDecoder1::value);
    using ResultItemValue2 = decltype(TValueDecoder2::value);
    static_assert(std::same_as<ResultItemValue1, ResultItemValue2>);
    using ResultItemValue = ResultItemValue1;

    using ResultItem = std::pair<ResultItemKey, ResultItemValue>;

    static ResultItem decode_kv_pair(std::pair<Bytes, Bytes>&& kv_pair) {
        if constexpr (std::same_as<ResultItem, std::pair<Bytes, Bytes>>) {
            return std::move(kv_pair);
        }

        TKeyDecoder2 key_decoder;
        key_decoder.decode_word(kv_pair.first);
        ResultItemKey& key = key_decoder.value;

        TValueDecoder2 value_decoder;
        value_decoder.decode_word(kv_pair.second);
        ResultItemValue& value = value_decoder.value;

        return ResultItem{std::move(key), std::move(value)};
    }

    static constexpr auto kDecodeKVPairFunc = [](std::pair<Bytes, Bytes>&& kv_pair) -> ResultItem {
        return decode_kv_pair(std::move(kv_pair));
    };

    auto exec(const Key& key_start, const Key& key_end, bool ascending) {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        return silkworm::views::merge_unique(
                   query1_.exec(key_start, key_end, ascending),
                   query2_.exec(key_start, key_end, ascending),
                   silkworm::views::MergeUniqueCompareFunc{},
                   PairGetFirst<Bytes, Bytes>{},
                   PairGetFirst<Bytes, Bytes>{}) |
               std::views::transform(kDecodeKVPairFunc);
    }

  private:
    kvdb::DomainRangeLatestQuery<TKeyEncoder1, kvdb::RawDecoder<Bytes>, kvdb::RawDecoder<Bytes>> query1_;
    snapshots::DomainRangeLatestQuery<TKeyEncoder2, snapshots::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>> query2_;
};

}  // namespace silkworm::datastore