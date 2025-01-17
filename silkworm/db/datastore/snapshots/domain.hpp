/*
   Copyright 2024 The Silkworm Authors

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

#include "bloom_filter/bloom_filter.hpp"
#include "btree/btree_index.hpp"
#include "history.hpp"
#include "rec_split/accessor_index.hpp"
#include "segment/kv_segment_reader.hpp"

namespace silkworm::snapshots {

struct Domain {
    const segment::KVSegmentFileReader& kv_segment;
    const rec_split::AccessorIndex* accessor_index{nullptr};
    const bloom_filter::BloomFilter& existence_index;
    const btree::BTreeIndex& btree_index;
    std::optional<History> history;
};

}  // namespace silkworm::snapshots
