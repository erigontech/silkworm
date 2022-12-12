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

namespace sux::function {

template <>
const size_t RecSplit8::lower_aggr = RecSplit8::SplitStrategy::lower_aggr;
template <>
const size_t RecSplit8::upper_aggr = RecSplit8::SplitStrategy::upper_aggr;
template <>
const array<uint32_t, MAX_BUCKET_SIZE> RecSplit8::memo = RecSplit8::fill_golomb_rice();

}  // namespace sux::function
