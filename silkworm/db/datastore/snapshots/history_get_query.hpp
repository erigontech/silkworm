// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../common/timestamp.hpp"
#include "basic_queries.hpp"
#include "common/codec.hpp"
#include "common/raw_codec.hpp"
#include "inverted_index_seek_query.hpp"
#include "snapshot_repository_ro_access.hpp"

namespace silkworm::snapshots {

template <
    EncoderConcept TKeyEncoder,
    DecoderConcept TValueDecoder,
    const SegmentAndAccessorIndexNames& segment_names>
struct HistoryGetQuery {
    explicit HistoryGetQuery(const SnapshotRepositoryROAccess& repository)
        : timestamp_query_{
              repository,
              [](const SnapshotBundle& bundle) { return bundle.history(segment_names.front()).inverted_index; },
              [&]() { return repository.inverted_index_seek_cache(segment_names.front()); },
          },
          value_query_{repository} {}

    using Key = decltype(TKeyEncoder::value);
    using Value = decltype(TValueDecoder::value);
    using AccessorIndexKey = typename HistoryAccessorIndexKeyEncoder<TKeyEncoder>::Value;

    std::optional<Value> exec(const Key& key, datastore::Timestamp timestamp) {
        auto result = timestamp_query_.exec(key, timestamp);
        return result ? value_query_.exec(*result, AccessorIndexKey{*result, key}) : std::nullopt;
    }

  private:
    InvertedIndexSeekQuery<TKeyEncoder> timestamp_query_;
    FindByTimestampMapQuery<FindByKeySegmentQuery<HistoryAccessorIndexKeyEncoder<TKeyEncoder>, TValueDecoder, segment_names>> value_query_;
};

}  // namespace silkworm::snapshots
