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
              [](const SnapshotBundle& bundle) { return bundle.domain(segment_names.front()).history->inverted_index; },
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
