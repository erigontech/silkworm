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

#include "pattern_aggregator.hpp"

#include <string_view>
#include <vector>

#include <catch2/catch.hpp>

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
