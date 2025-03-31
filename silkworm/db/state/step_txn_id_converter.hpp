// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/base.hpp>
#include <silkworm/db/datastore/common/step.hpp>
#include <silkworm/db/datastore/common/step_timestamp_converter.hpp>

namespace silkworm::db::state {

//! Scale factor to convert from-to txn id values in temporal snapshot file names
inline constexpr size_t kStepSizeForTemporalSnapshots = 1'562'500;  // = 100M / 64

inline constexpr datastore::StepToTimestampConverter kStepToTxnIdConverter{kStepSizeForTemporalSnapshots};

}  // namespace silkworm::db::state
