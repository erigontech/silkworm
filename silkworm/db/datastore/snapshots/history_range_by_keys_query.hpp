// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iterator>
#include <ranges>
#include <utility>
#include <vector>

#include <silkworm/core/common/assert.hpp>

#include "../common/entity_name.hpp"
#include "../common/pair_get.hpp"
#include "../common/ranges/caching_view.hpp"
#include "../common/ranges/lazy_view.hpp"
#include "../common/ranges/merge_many_view.hpp"
#include "../common/ranges/owning_view.hpp"
#include "common/codec.hpp"
#include "history.hpp"
#include "inverted_index_lower_bound_key_offset_segment_query.hpp"
#include "snapshot_bundle.hpp"
#include "snapshot_repository_ro_access.hpp"

namespace silkworm::snapshots {

struct HistoryRangeByKeysSegmentQuery {
    explicit HistoryRangeByKeysSegmentQuery(History entity)
        : entity_{std::move(entity)} {}
    explicit HistoryRangeByKeysSegmentQuery(
        const SnapshotBundle& bundle,
        datastore::EntityName entity_name)
        : entity_{bundle.history(entity_name)} {}

    using ResultItem = std::pair<Bytes, Bytes>;

    using AccessorIndexKeyEncoder = HistoryAccessorIndexKeyEncoder<RawEncoder<ByteView>>;

    std::optional<ResultItem> lookup_kv_pair(
        datastore::Timestamp timestamp,
        bool ascending,
        Bytes key_data,
        const elias_fano::EliasFanoList32& key_timestamps) const {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        // find the first key timestamp within the ts_range
        auto ts_opt = key_timestamps.seek(timestamp);
        if (!ts_opt) return std::nullopt;
        datastore::Timestamp ts = ts_opt->second;

        // query history value using the timestamp and key_data
        static const SegmentAndAccessorIndexNames kDummySegmentNames{datastore::EntityName{{}}, datastore::EntityName{{}}, datastore::EntityName{{}}};
        FindByKeySegmentQuery<AccessorIndexKeyEncoder, RawDecoder<Bytes>, kDummySegmentNames> value_query{entity_.segment_and_index()};
        auto value_opt = value_query.exec(AccessorIndexKeyEncoder::Value{ts, key_data});
        if (!value_opt) return std::nullopt;

        return std::pair{std::move(key_data), std::move(*value_opt)};
    }

    auto exec_with_eager_begin(Bytes key_start, Bytes key_end, datastore::Timestamp timestamp, bool ascending) {  // NOLINT(*-unnecessary-value-param)
        SILKWORM_ASSERT(ascending);                                                                               // descending is not implemented

        InvertedIndexLowerBoundKeyOffsetSegmentQuery lower_bound_query{entity_.inverted_index};
        std::optional<size_t> offset = lower_bound_query.exec(key_start);

        auto ii_reader = entity_.inverted_index.kv_segment_reader<RawDecoder<Bytes>>();
        auto begin_it = offset ? ii_reader.seek(*offset) : ii_reader.end();

        auto lookup_kv_pair_func = [query = *this, timestamp, ascending](std::pair<Bytes&, elias_fano::EliasFanoList32&> ii_entry) {
            return query.lookup_kv_pair(timestamp, ascending, std::move(ii_entry.first), ii_entry.second);
        };

        return std::ranges::subrange{std::move(begin_it), ii_reader.end()} |
               std::views::take_while([key_end = std::move(key_end)](auto&& ii_entry) { return ii_entry.first < key_end; }) |
               std::views::transform(std::move(lookup_kv_pair_func)) |
               silkworm::views::caching |
               std::views::filter([](const std::optional<ResultItem>& result_opt) { return result_opt.has_value(); }) |
               std::views::transform([](std::optional<ResultItem>& result_opt) -> ResultItem { return std::move(*result_opt); }) |
               silkworm::views::caching;
    }

    auto exec(Bytes key_start, Bytes key_end, datastore::Timestamp timestamp, bool ascending) {
        auto exec_func = [query = *this, key_start = std::move(key_start), key_end = std::move(key_end), timestamp, ascending]() mutable {
            return query.exec_with_eager_begin(std::move(key_start), std::move(key_end), timestamp, ascending);
        };
        return silkworm::ranges::lazy(std::move(exec_func));
    }

  private:
    History entity_;
};

template <
    EncoderConcept TKeyEncoder,
    DecoderConcept TKeyDecoder, DecoderConcept TValueDecoder>
struct HistoryRangeByKeysQuery {
    const SnapshotRepositoryROAccess& repository;
    datastore::EntityName entity_name;

    using Key = decltype(TKeyEncoder::value);
    using ResultItemKey = decltype(TKeyDecoder::value);
    using ResultItemValue = decltype(TValueDecoder::value);
    using ResultItem = std::pair<ResultItemKey, ResultItemValue>;

    static ResultItem decode_kv_pair(std::pair<Bytes, Bytes>&& kv_pair) {
        if constexpr (std::same_as<ResultItem, std::pair<Bytes, Bytes>>) {
            return std::move(kv_pair);
        }

        Decoder::Word key_word{std::move(kv_pair.first)};
        TKeyDecoder key_decoder;
        key_decoder.decode_word(key_word);
        ResultItemKey& key = key_decoder.value;

        Decoder::Word value_word{std::move(kv_pair.second)};
        TValueDecoder value_decoder;
        value_decoder.decode_word(value_word);
        ResultItemValue& value = value_decoder.value;

        return ResultItem{std::move(key), std::move(value)};
    }

    static constexpr auto kDecodeKVPairFunc = [](std::pair<Bytes, Bytes>& kv_pair) -> ResultItem {
        return decode_kv_pair(std::move(kv_pair));
    };

    auto exec(const Key& key_start, const Key& key_end, datastore::Timestamp timestamp, bool ascending) {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        TKeyEncoder key_start_encoder;
        key_start_encoder.value = key_start;
        ByteView key_start_data = key_start_encoder.encode_word();

        TKeyEncoder key_end_encoder;
        key_end_encoder.value = key_end;
        ByteView key_end_data = key_end_encoder.encode_word();

        auto results_in_bundle = [entity_name1 = this->entity_name, key_start_data = Bytes{key_start_data}, key_end_data = Bytes{key_end_data}, timestamp, ascending](const std::shared_ptr<SnapshotBundle>& bundle_ptr) {
            const SnapshotBundle& bundle = *bundle_ptr;
            HistoryRangeByKeysSegmentQuery query{bundle, entity_name1};
            return query.exec(key_start_data, key_end_data, timestamp, ascending);
        };

        auto bundle_results = silkworm::ranges::owning_view(repository.bundles_intersecting_range(datastore::TimestampRange{timestamp, datastore::kMaxTimestamp}, ascending)) |
                              std::views::transform(std::move(results_in_bundle));

        auto results = silkworm::views::merge_unique_many(
            std::move(bundle_results),
            silkworm::views::MergeCompareFunc{},
            PairGetFirst<HistoryRangeByKeysSegmentQuery::ResultItem::first_type, HistoryRangeByKeysSegmentQuery::ResultItem::second_type>{});

        return silkworm::ranges::owning_view(std::move(results)) |
               std::views::transform(kDecodeKVPairFunc) |
               silkworm::views::caching;
    }
};

}  // namespace silkworm::snapshots
