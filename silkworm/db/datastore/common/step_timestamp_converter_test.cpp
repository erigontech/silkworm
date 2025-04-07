// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "step_timestamp_converter.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::datastore {

TEST_CASE("StepToTimestampConverter") {
    static constexpr size_t kStepSize = 1000;
    StepToTimestampConverter converter{kStepSize};

    SECTION("Step to Timestamp and back") {
        Step step{10};
        Timestamp ts = converter.timestamp_from_step(step);
        CHECK(ts == kStepSize * 10);
        CHECK(converter.step_from_timestamp(ts) == step);

        CHECK(converter.timestamp_from_step(Step{0}) == 0);
        CHECK(converter.timestamp_from_step(Step{500}) == kStepSize * 500);
    }

    SECTION("Step limits") {
        CHECK(converter.step_from_timestamp(kMaxTimestamp) == kMaxStep);
        CHECK(converter.timestamp_from_step(kMaxStep) == kMaxTimestamp);
    }

    SECTION("StepRange to TimestampRange and back") {
        StepRange range{Step{10}, Step{20}};
        const TimestampRange ts_range = converter.timestamp_range_from_step_range(range);
        CHECK(ts_range == TimestampRange{kStepSize * 10, kStepSize * 20});
        CHECK(converter.step_range_from_timestamp_range(ts_range) == range);

        CHECK(converter.timestamp_range_from_step_range({Step{0}, Step{0}}) == TimestampRange{0, 0});
        CHECK(converter.timestamp_range_from_step_range({Step{0}, Step{500}}) == TimestampRange{0, kStepSize * 500});
    }

    SECTION("StepRange limits") {
        CHECK(converter.step_range_from_timestamp_range({kMaxTimestamp, kMaxTimestamp}) == StepRange{kMaxStep, kMaxStep});
        CHECK(converter.timestamp_range_from_step_range({kMaxStep, kMaxStep}) == TimestampRange{kMaxTimestamp, kMaxTimestamp});
        CHECK_THROWS(converter.step_range_from_timestamp_range({0, kMaxTimestamp - 1}));
    }
}

}  // namespace silkworm::datastore
