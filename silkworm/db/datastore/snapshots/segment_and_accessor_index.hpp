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

#include <array>

#include "../common/entity_name.hpp"
#include "rec_split/accessor_index.hpp"
#include "segment/segment_reader.hpp"

namespace silkworm::snapshots {

struct SegmentAndAccessorIndex {
    const segment::SegmentFileReader& segment;
    const rec_split::AccessorIndex& index;
};

using SegmentAndAccessorIndexNames = std::array<datastore::EntityName, 3>;

struct SegmentAndAccessorIndexProvider {
    virtual ~SegmentAndAccessorIndexProvider() = default;
    virtual SegmentAndAccessorIndex segment_and_accessor_index(
        const SegmentAndAccessorIndexNames& names) const = 0;
};

}  // namespace silkworm::snapshots
