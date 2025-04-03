// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include "bloom_filter/bloom_filter.hpp"
#include "btree/btree_index.hpp"
#include "rec_split/accessor_index.hpp"
#include "segment/kv_segment_reader.hpp"

namespace silkworm::snapshots {

struct Domain {
    const segment::KVSegmentFileReader& kv_segment;
    const rec_split::AccessorIndex* accessor_index{nullptr};
    const bloom_filter::BloomFilter& existence_index;
    const btree::BTreeIndex& btree_index;
};

}  // namespace silkworm::snapshots
