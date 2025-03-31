// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/common/step_timestamp_converter.hpp>

namespace silkworm::db::blocks {

//! Scale factor to convert from-to block number values in block snapshot file names
inline constexpr size_t kStepSizeForBlockSnapshots = 1'000;

inline constexpr datastore::StepToTimestampConverter kStepToBlockNumConverter{kStepSizeForBlockSnapshots};

}  // namespace silkworm::db::blocks
