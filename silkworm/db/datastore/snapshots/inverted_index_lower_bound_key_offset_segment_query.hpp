// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/core/common/bytes.hpp>

#include "inverted_index.hpp"

namespace silkworm::snapshots {

struct InvertedIndexLowerBoundKeyOffsetSegmentQuery {
    InvertedIndex entity;

    std::optional<size_t> exec(ByteView key);
};

}  // namespace silkworm::snapshots
