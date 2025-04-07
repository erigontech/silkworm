// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "step_timestamp_converter.hpp"

#include <silkworm/infra/common/ensure.hpp>

namespace silkworm::datastore {

Step StepToTimestampConverter::step_from_timestamp(Timestamp t) const {
    if (t == kMaxTimestamp) return kMaxStep;
    return Step{static_cast<size_t>(t / step_size)};
}

Timestamp StepToTimestampConverter::timestamp_from_step(Step s) const {
    if (s == kMaxStep) return kMaxTimestamp;
    return s.value * step_size;
}

StepRange StepToTimestampConverter::step_range_from_timestamp_range(TimestampRange range) const {
    if (range.end == kMaxTimestamp) {
        return StepRange{step_from_timestamp(range.start), kMaxStep};
    }
    ensure(range.end <= kMaxTimestamp - step_size + 1, "step_range_from_timestamp_range: end step overflow");
    Step end = step_from_timestamp(range.end + step_size - 1);
    return StepRange{step_from_timestamp(range.start), end};
}

}  // namespace silkworm::datastore
