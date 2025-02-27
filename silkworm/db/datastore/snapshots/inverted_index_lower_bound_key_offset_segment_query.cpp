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

#include "inverted_index_lower_bound_key_offset_segment_query.hpp"

#include <algorithm>

#include <silkworm/core/common/assert.hpp>

#include "common/raw_codec.hpp"
#include "common/util/iterator/index_range.hpp"

namespace silkworm::snapshots {

std::optional<size_t> InvertedIndexLowerBoundKeyOffsetSegmentQuery::exec(ByteView key) {
    size_t count = entity.kv_segment.item_count();
    IndexRange index_range{0, count};
    IndexRange::Iterator it = std::lower_bound(index_range.begin(), index_range.end(), key, [this](size_t i, ByteView target_key) {
        std::optional<size_t> offset = entity.accessor_index.lookup_by_data_id(entity.accessor_index.base_data_id() + i);
        SILKWORM_ASSERT(offset);
        if (!offset) return true;
        std::optional<Bytes> key_opt = segment::KVSegmentKeysReader<RawDecoder<Bytes>>{entity.kv_segment}.seek_one(*offset);
        if (!key_opt) return true;
        return *key_opt < target_key;
    });
    if (*it < count) {
        return entity.accessor_index.lookup_by_data_id(entity.accessor_index.base_data_id() + *it);
    }
    return std::nullopt;
}

}  // namespace silkworm::snapshots
