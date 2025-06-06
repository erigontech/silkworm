// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <ranges>

#include "../common/ranges/if_view.hpp"
#include "../common/ranges/owning_view.hpp"
#include "../common/timestamp.hpp"
#include "common/raw_codec.hpp"
#include "elias_fano/elias_fano_list.hpp"
#include "inverted_index.hpp"
#include "snapshot_bundle.hpp"

namespace silkworm::snapshots {

inline auto timestamp_range_filter(InvertedIndexTimestampList list, datastore::TimestampRange ts_range, bool ascending) {
    using Iterator = InvertedIndexTimestampList::Iterator;

    size_t start = 0;
    size_t end = list.size();
    if (ascending) {
        auto start_opt = list.seek(ts_range.start, /*reverse=*/false);
        start = start_opt ? start_opt->first : end;
    } else if (ts_range.size() > 0) {
        auto last_opt = list.seek(ts_range.end - 1, /*reverse=*/true);
        end = last_opt ? last_opt->first + 1 : start;
    } else {
        start = end;
    }

    auto range_from_list = [ts_range, ascending, start, end](const InvertedIndexTimestampList& list1) {
        auto list_range = [&list1, start, end]() { return std::ranges::subrange{Iterator{list1, start}, Iterator{list1, end}}; };
        return silkworm::views::if_view(
            ascending,
            list_range() | std::views::all | std::views::take_while([ts_range](uint64_t ts) { return ts < ts_range.end; }),
            list_range() | std::views::reverse | std::views::take_while([ts_range](uint64_t ts) { return ts >= ts_range.start; }));
    };

    return std::ranges::single_view{std::move(list)} |
           std::views::transform(std::move(range_from_list)) |
           std::views::join;
}

template <EncoderConcept TKeyEncoder>
struct InvertedIndexFindByKeySegmentQuery {
    explicit InvertedIndexFindByKeySegmentQuery(
        InvertedIndex entity)
        : entity_{entity} {}
    explicit InvertedIndexFindByKeySegmentQuery(
        const SnapshotBundle& bundle,
        datastore::EntityName entity_name)
        : entity_{bundle.inverted_index(entity_name)} {}

    using Key = decltype(TKeyEncoder::value);

    std::optional<InvertedIndexTimestampList> exec(Key key) {
        TKeyEncoder key_encoder;
        key_encoder.value = std::move(key);
        ByteView key_data = key_encoder.encode_word();
        return exec_raw(key_data);
    }

    std::optional<InvertedIndexTimestampList> exec_raw(ByteView key_data) {
        auto offset = entity_.accessor_index.lookup_by_key(key_data);
        if (!offset) {
            return std::nullopt;
        }

        auto reader = entity_.kv_segment_reader<RawDecoder<Bytes>>();
        std::optional<std::pair<Bytes, InvertedIndexTimestampList>> result = reader.seek_one(*offset);

        // ensure that the found key matches to avoid lookup_by_key false positives
        if (result && (result->first == key_data)) {
            return std::move(result->second);
        }

        return std::nullopt;
    }

    auto exec_filter(Key key, datastore::TimestampRange ts_range, bool ascending) {
        return timestamp_range_filter(exec(std::move(key)).value_or(InvertedIndexTimestampList{}), ts_range, ascending);
    }

  private:
    InvertedIndex entity_;
};

}  // namespace silkworm::snapshots
