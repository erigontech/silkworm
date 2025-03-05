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

#include <ranges>

#include "../common/entity_name.hpp"
#include "../common/ranges/caching_view.hpp"
#include "../common/ranges/owning_view.hpp"
#include "../common/timestamp.hpp"
#include "common/raw_codec.hpp"
#include "history.hpp"
#include "history_accessor_index.hpp"
#include "snapshot_repository_ro_access.hpp"

namespace silkworm::snapshots {

template <DecoderConcept TKeyDecoder, DecoderConcept TValueDecoder>
struct HistoryRangeSegmentQuery {
    explicit HistoryRangeSegmentQuery(History entity) : entity_{entity} {}
    HistoryRangeSegmentQuery(const SnapshotBundle& bundle, datastore::EntityName entity_name)
        : entity_{bundle.history(entity_name)} {}

    using Key = decltype(TKeyDecoder::value);
    using Value = decltype(TValueDecoder::value);
    using ResultItem = std::pair<Key, Value>;
    using Word = snapshots::Decoder::Word;
    using AccessorIndexKeyEncoder = HistoryAccessorIndexKeyEncoder<RawEncoder<ByteView>>;

    std::optional<ResultItem> lookup_kv_pair(
        datastore::TimestampRange ts_range,
        bool ascending,
        Bytes key_data,
        const elias_fano::EliasFanoList32& key_timestamps) const {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        // find the first key timestamp within the ts_range
        auto ts_opt = key_timestamps.seek(ts_range.start);
        if (!ts_opt) return std::nullopt;
        datastore::Timestamp ts = ts_opt->second;
        if (ts >= ts_range.end) return std::nullopt;

        // query history value using the timestamp and key_data
        static constexpr SegmentAndAccessorIndexNames kDummySegmentNames;
        FindByKeySegmentQuery<AccessorIndexKeyEncoder, TValueDecoder, kDummySegmentNames> value_query{entity_.segment_and_index()};
        auto value_opt = value_query.exec(AccessorIndexKeyEncoder::Value{ts, key_data});
        if (!value_opt) return std::nullopt;

        // return the key-value pair
        TKeyDecoder key_decoder;
        Word key_data_word{std::move(key_data)};
        key_decoder.decode_word(key_data_word);
        return ResultItem{std::move(key_decoder.value), std::move(*value_opt)};
    }

    auto exec(datastore::TimestampRange ts_range, bool ascending) {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        auto lookup_kv_pair_func = [query = *this, ts_range, ascending](std::pair<Bytes&, elias_fano::EliasFanoList32&>&& ii_entry) {
            return query.lookup_kv_pair(ts_range, ascending, std::move(ii_entry.first), ii_entry.second);
        };

        auto ii_reader = entity_.inverted_index.kv_segment_reader<RawDecoder<Bytes>>();

        return ii_reader |
               std::views::transform(std::move(lookup_kv_pair_func)) |
               silkworm::views::caching |
               std::views::filter([](const std::optional<ResultItem>& result_opt) { return result_opt.has_value(); }) |
               std::views::transform([](std::optional<ResultItem>& result_opt) -> ResultItem { return std::move(*result_opt); }) |
               silkworm::views::caching;
    }

  private:
    History entity_;
};

template <DecoderConcept TKeyDecoder, DecoderConcept TValueDecoder>
struct HistoryRangeQuery {
    HistoryRangeQuery(
        const SnapshotRepositoryROAccess& repository,
        datastore::EntityName entity_name)
        : repository_{repository},
          entity_name_{std::move(entity_name)} {}

    using Key = decltype(TKeyDecoder::value);
    using Value = decltype(TValueDecoder::value);
    using ResultItem = std::pair<Key, Value>;

    auto exec(datastore::TimestampRange ts_range, bool ascending) {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        auto results_in_bundle = [entity_name = entity_name_, ts_range, ascending](const std::shared_ptr<SnapshotBundle>& bundle) {
            HistoryRangeSegmentQuery<TKeyDecoder, TValueDecoder> query{*bundle, entity_name};
            return query.exec(ts_range, ascending);
        };

        return silkworm::ranges::owning_view(repository_.bundles_intersecting_range(ts_range, ascending)) |
               std::views::transform(std::move(results_in_bundle)) |
               std::views::join;
    }

  private:
    const SnapshotRepositoryROAccess& repository_;
    datastore::EntityName entity_name_;
};

}  // namespace silkworm::snapshots
