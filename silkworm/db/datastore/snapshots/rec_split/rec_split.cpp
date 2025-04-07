// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "rec_split.hpp"

namespace silkworm::snapshots::rec_split {

template <>
const size_t RecSplit8::kLowerAggregationBound = RecSplit8::SplitStrategy::kLowerAggregationBound;
template <>
const size_t RecSplit8::kUpperAggregationBound = RecSplit8::SplitStrategy::kUpperAggregationBound;
template <>
const std::array<uint32_t, kMaxBucketSize> RecSplit8::kMemo = RecSplit8::fill_golomb_rice();

}  // namespace silkworm::snapshots::rec_split
