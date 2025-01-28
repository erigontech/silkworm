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

#include <optional>
#include <ranges>

#include "../common/owning_view.hpp"
#include "../common/timestamp.hpp"
#include "common/raw_codec.hpp"
#include "elias_fano/elias_fano_list.hpp"
#include "inverted_index.hpp"
#include "snapshot_bundle.hpp"

namespace silkworm::snapshots {

template <bool ascending = true>
auto timestamp_range_filter(elias_fano::EliasFanoList32 list, datastore::TimestampRange ts_range) {
    if constexpr (ascending) {
        return silkworm::ranges::owning_view(std::move(list)) | std::views::all | std::views::filter(ts_range.contains_predicate());
    } else {
        return silkworm::ranges::owning_view(std::move(list)) | std::views::reverse | std::views::filter(ts_range.contains_predicate());
    }
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

    std::optional<elias_fano::EliasFanoList32> exec(Key key) {
        TKeyEncoder key_encoder;
        key_encoder.value = std::move(key);
        ByteView key_data = key_encoder.encode_word();

        auto offset = entity_.accessor_index.lookup_by_key(key_data);
        if (!offset) {
            return std::nullopt;
        }

        auto reader = entity_.kv_segment_reader<RawDecoder<Bytes>>();
        std::optional<std::pair<Bytes, elias_fano::EliasFanoList32>> result = reader.seek_one(*offset);

        // ensure that the found key matches to avoid lookup_by_key false positives
        if (result && (result->first == key_data)) {
            return std::move(result->second);
        }

        return std::nullopt;
    }

    template <bool ascending = true>
    auto exec_filter(Key key, datastore::TimestampRange ts_range) {
        return timestamp_range_filter<ascending>(exec(std::move(key)).value_or(elias_fano::EliasFanoList32::empty_list()), ts_range);
    }

  private:
    InvertedIndex entity_;
};

}  // namespace silkworm::snapshots
