/*
   Copyright 2022 The Silkworm Authors

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

#include "rec_split.hpp"

namespace silkworm::snapshots::rec_split {

template <>
const std::size_t RecSplit8::kLowerAggregationBound = RecSplit8::SplitStrategy::kLowerAggregationBound;
template <>
const std::size_t RecSplit8::kUpperAggregationBound = RecSplit8::SplitStrategy::kUpperAggregationBound;
template <>
const std::array<uint32_t, kMaxBucketSize> RecSplit8::kMemo = RecSplit8::fill_golomb_rice();

}  // namespace silkworm::snapshots::rec_split
