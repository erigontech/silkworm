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

#include <functional>
#include <optional>

#include "../common/timestamp.hpp"
#include "common/codec.hpp"
#include "inverted_index.hpp"
#include "inverted_index_find_by_key_segment_query.hpp"
#include "snapshot_bundle.hpp"
#include "snapshot_repository_ro_access.hpp"

namespace silkworm::snapshots {

template <EncoderConcept TKeyEncoder>
struct InvertedIndexSeekSegmentQuery {
    explicit InvertedIndexSeekSegmentQuery(InvertedIndex entity)
        : query_{std::move(entity)} {}

    using Key = decltype(TKeyEncoder::value);

    std::optional<datastore::Timestamp> exec(Key key, datastore::Timestamp timestamp) {
        auto list_opt = query_.exec(std::move(key));
        if (!list_opt) {
            return std::nullopt;
        }

        elias_fano::EliasFanoList32& list = *list_opt;
        auto result = list.seek(timestamp);
        return result ? std::optional{result->second} : std::nullopt;
    }

  private:
    InvertedIndexFindByKeySegmentQuery<TKeyEncoder> query_;
};

template <EncoderConcept TKeyEncoder>
struct InvertedIndexSeekQuery {
    explicit InvertedIndexSeekQuery(
        const SnapshotRepositoryROAccess& repository,
        std::function<InvertedIndex(const SnapshotBundle&)> entity_provider)
        : repository_{repository},
          entity_provider_{std::move(entity_provider)} {}

    using Key = decltype(TKeyEncoder::value);

    std::optional<datastore::Timestamp> exec(Key key, datastore::Timestamp timestamp) {
        datastore::TimestampRange ts_range{timestamp, repository_.max_timestamp_available() + 1};
        for (auto& bundle_ptr : repository_.bundles_intersecting_range(ts_range, /* ascending = */ true)) {
            const SnapshotBundle& bundle = *bundle_ptr;
            InvertedIndexSeekSegmentQuery<TKeyEncoder> query{entity_provider_(bundle)};
            auto result = query.exec(key, timestamp);
            if (result) {
                return result;
            }
        }
        return std::nullopt;
    }

  private:
    const SnapshotRepositoryROAccess& repository_;
    std::function<InvertedIndex(const SnapshotBundle&)> entity_provider_;
};

}  // namespace silkworm::snapshots
