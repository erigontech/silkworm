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
    explicit InvertedIndexSeekSegmentQuery(InvertedIndex entity, InvertedIndexCache* cache)
        : query_{std::move(entity)}, cache_{cache} {}

    using Key = decltype(TKeyEncoder::value);

    std::optional<datastore::Timestamp> exec(Key key, datastore::Timestamp timestamp) {
        TKeyEncoder key_encoder;
        key_encoder.value = std::move(key);
        ByteView key_data = key_encoder.encode_word();
        return exec_raw(key_data, timestamp);
    }

    std::optional<datastore::Timestamp> exec_raw(ByteView key, datastore::Timestamp timestamp) {
        std::optional<InvertedIndexTimestamps> ts_pair;
        uint64_t key_hash_hi{0};

        if (cache_) {
            if (std::tie(ts_pair, key_hash_hi) = cache_->get(key); ts_pair) {
                if (ts_pair->requested <= timestamp) {
                    if (timestamp <= ts_pair->found) {
                        return ts_pair->found;
                    }
                    if (ts_pair->found == 0) {
                        return std::nullopt;
                    }
                }
            }
        }

        auto list_opt = query_.exec_raw(key);
        if (!list_opt) {
            return std::nullopt;
        }

        elias_fano::EliasFanoList32& list = *list_opt;
        const auto seek_result = list.seek(timestamp);
        if (!seek_result) {
            return std::nullopt;
        }
        const auto [_, higher_or_equal_ts] = *seek_result;

        if (cache_ && higher_or_equal_ts > timestamp) {
            cache_->put(key_hash_hi, InvertedIndexTimestamps{.requested = timestamp, .found = higher_or_equal_ts});
        }

        return higher_or_equal_ts;
    }

  private:
    InvertedIndexFindByKeySegmentQuery<TKeyEncoder> query_;
    InvertedIndexCache* cache_;
};

template <EncoderConcept TKeyEncoder>
struct InvertedIndexSeekQuery {
    explicit InvertedIndexSeekQuery(
        const SnapshotRepositoryROAccess& repository,
        std::function<InvertedIndex(const SnapshotBundle&)> entity_provider,
        std::function<InvertedIndexCache*()> cache_provider)
        : repository_{repository},
          entity_provider_{std::move(entity_provider)},
          cache_provider_{std::move(cache_provider)} {}

    using Key = decltype(TKeyEncoder::value);

    std::optional<datastore::Timestamp> exec(Key key, datastore::Timestamp timestamp) {
        InvertedIndexCache* cache = cache_provider_();

        TKeyEncoder key_encoder;
        key_encoder.value = std::move(key);
        ByteView key_data = key_encoder.encode_word();

        datastore::TimestampRange ts_range{timestamp, repository_.max_timestamp_available() + 1};
        for (auto& bundle_ptr : repository_.bundles_intersecting_range(ts_range, /*ascending=*/true)) {
            const SnapshotBundle& bundle = *bundle_ptr;
            InvertedIndexSeekSegmentQuery<TKeyEncoder> query{entity_provider_(bundle), cache};
            auto result = query.exec_raw(key_data, timestamp);
            if (result) {
                return result;
            }
        }
        if (cache) {
            cache->put(key_data, InvertedIndexTimestamps{.requested = timestamp, .found = 0});
        }
        return std::nullopt;
    }

  private:
    const SnapshotRepositoryROAccess& repository_;
    std::function<InvertedIndex(const SnapshotBundle&)> entity_provider_;
    std::function<InvertedIndexCache*()> cache_provider_;
};

}  // namespace silkworm::snapshots
