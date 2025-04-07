// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "step.hpp"
#include "timestamp.hpp"

namespace silkworm::datastore {

struct StepToTimestampConverter {
    size_t step_size;

    Step step_from_timestamp(Timestamp t) const;
    Timestamp timestamp_from_step(Step s) const;

    StepRange step_range_from_timestamp_range(TimestampRange range) const;
    TimestampRange timestamp_range_from_step_range(StepRange range) const {
        return TimestampRange{timestamp_from_step(range.start), timestamp_from_step(range.end)};
    }
};

}  // namespace silkworm::datastore
