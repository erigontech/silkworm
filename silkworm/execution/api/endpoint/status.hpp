// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>

namespace silkworm::execution::api {

enum ExecutionStatus : uint8_t {
    kSuccess,
    kBadBlock,
    kTooFarAway,
    kMissingSegment,
    kInvalidForkchoice,
    kBusy,
};

inline bool success(ExecutionStatus status) { return status == ExecutionStatus::kSuccess; }

}  // namespace silkworm::execution::api
