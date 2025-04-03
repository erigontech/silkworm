// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
