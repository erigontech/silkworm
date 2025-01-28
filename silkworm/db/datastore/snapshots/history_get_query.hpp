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
#include "snapshot_repository_ro_access.hpp"

namespace silkworm::snapshots {

template <
    EncoderConcept TKeyEncoder,
    DecoderConcept TValueDecoder,
    const SegmentAndAccessorIndexNames* segment_names>
struct HistoryGetQuery {
    explicit HistoryGetQuery(const SnapshotRepositoryROAccess& repository)
        : query_{repository} {}

    using Key = decltype(TKeyEncoder::value);
    using Value = decltype(TValueDecoder::value);

    std::optional<Value> exec(const Key& key, datastore::Timestamp timestamp) {
        // TODO
        return query_.exec(0, key);
    }

  private:
    FindByTimestampMapQuery<FindByKeySegmentQuery<TKeyEncoder, segment::SegmentReader<TValueDecoder>, segment_names>> query_;
};

}  // namespace silkworm::snapshots
