// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
        TKeyEncoder key_encoder;
        key_encoder.value = std::move(key);
        ByteView key_data = key_encoder.encode_word();
        return exec_raw(key_data, timestamp);
    }

    std::optional<datastore::Timestamp> exec_raw(ByteView key, datastore::Timestamp timestamp) {
        auto list_opt = query_.exec_raw(key);
        if (!list_opt) {
            return std::nullopt;
        }

        InvertedIndexTimestampList& list = *list_opt;
        const auto seek_result = list.seek(timestamp);
        if (seek_result) {
            return seek_result->second;
        }
        return std::nullopt;
    }

  private:
    InvertedIndexFindByKeySegmentQuery<TKeyEncoder> query_;
};

struct InvertedIndexSeekQueryRawNoCache {
    const SnapshotRepositoryROAccess& repository_;
    std::function<InvertedIndex(const SnapshotBundle&)> entity_provider_;

    std::optional<datastore::Timestamp> exec(ByteView key_data, datastore::Timestamp timestamp) {
        datastore::TimestampRange ts_range{timestamp, repository_.max_timestamp_available() + 1};
        for (auto& bundle_ptr : repository_.bundles_intersecting_range(ts_range, /*ascending=*/true)) {
            const SnapshotBundle& bundle = *bundle_ptr;
            InvertedIndexSeekSegmentQuery<RawEncoder<ByteView>> query{entity_provider_(bundle)};
            std::optional<datastore::Timestamp> result = query.exec_raw(key_data, timestamp);
            if (result) {
                return result;
            }
        }
        return std::nullopt;
    }
};

struct InvertedIndexSeekQueryRawWithCache {
    struct InvertedIndexSeekCacheData {
        datastore::Timestamp requested;
        std::optional<datastore::Timestamp> found;
    };

    using CacheType = QueryCache<InvertedIndexSeekCacheData>;
    static inline const datastore::EntityName kName{"InvertedIndexSeekQueryRawWithCache"};

    InvertedIndexSeekQueryRawWithCache(
        const SnapshotRepositoryROAccess& repository,
        std::function<InvertedIndex(const SnapshotBundle&)> entity_provider,
        CacheType* cache)
        : query_{repository, std::move(entity_provider)},
          cache_{cache} {}

    std::optional<datastore::Timestamp> exec(ByteView key_data, datastore::Timestamp timestamp) {
        if (!cache_) {
            return query_.exec(key_data, timestamp);
        }

        std::optional<InvertedIndexSeekCacheData> cached_data;
        uint64_t cache_key{0};
        std::tie(cached_data, cache_key) = cache_->get(key_data);
        if (cached_data && (cached_data->requested <= timestamp)) {
            if (!cached_data->found) {  // hit in cache but value not found
                return std::nullopt;
            }
            if (timestamp <= *cached_data->found) {
                return cached_data->found;
            }
        }

        std::optional<datastore::Timestamp> result = query_.exec(key_data, timestamp);
        bool found_equal = result && (*result == timestamp);
        if (!found_equal) {
            cache_->put(cache_key, {.requested = timestamp, .found = result});
        }
        return result;
    }

  private:
    InvertedIndexSeekQueryRawNoCache query_;
    CacheType* cache_;
};

template <EncoderConcept TKeyEncoder>
struct InvertedIndexSeekQuery {
    InvertedIndexSeekQuery(
        const SnapshotRepositoryROAccess& repository,
        std::function<InvertedIndex(const SnapshotBundle&)> entity_provider,
        InvertedIndexSeekQueryRawWithCache::CacheType* cache)
        : query_{repository, std::move(entity_provider), cache} {}

    using Key = decltype(TKeyEncoder::value);

    std::optional<datastore::Timestamp> exec(Key key, datastore::Timestamp timestamp) {
        TKeyEncoder key_encoder;
        key_encoder.value = std::move(key);
        ByteView key_data = key_encoder.encode_word();

        return query_.exec(key_data, timestamp);
    }

  private:
    InvertedIndexSeekQueryRawWithCache query_;
};

}  // namespace silkworm::snapshots
