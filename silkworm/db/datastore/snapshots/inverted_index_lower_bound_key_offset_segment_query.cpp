// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
