// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "pattern_aggregator.hpp"

#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/directories.hpp>

namespace silkworm::snapshots::seg {

static Bytes operator""_hex(const char* data, size_t size) {
    return from_hex(std::string_view{data, size}).value();
}

TEST_CASE("PatternAggregator") {
    TemporaryDirectory etl_work_path;
    PatternAggregator aggregator{etl_work_path.path()};
    aggregator.collect_pattern({"CAFE"_hex, 1});
    aggregator.collect_pattern({"BABE"_hex, 2});
    aggregator.collect_pattern({"FEED"_hex, 3});
    aggregator.collect_pattern({"BABE"_hex, 4});

    std::vector<PatternAggregator::Pattern> expected_patterns = {
        {"BABE"_hex, 6},
        {"FEED"_hex, 3},
        {"CAFE"_hex, 1},
    };

    auto actual_patterns = PatternAggregator::aggregate(std::move(aggregator));
    CHECK(actual_patterns == expected_patterns);
}

}  // namespace silkworm::snapshots::seg
