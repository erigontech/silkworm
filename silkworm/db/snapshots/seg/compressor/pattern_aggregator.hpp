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

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <vector>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::snapshots::seg {

class PatternAggregatorImpl;

/**
 * PatternAggregator aggregates top score unique patterns:
 * SELECT data, sum(score) FROM patterns GROUP BY data
 *     ORDER BY sum(score) DESC LIMIT kMaxPatterns
 * Since all patterns might take a lot of RAM, the ETL framework is used.
 */
class PatternAggregator {
  public:
    PatternAggregator(const std::filesystem::path& etl_work_path);
    ~PatternAggregator();

    PatternAggregator(PatternAggregator&& other) noexcept;
    PatternAggregator& operator=(PatternAggregator&& other) noexcept;

    struct Pattern {
        Bytes data;
        uint64_t score;

        friend bool operator==(const Pattern&, const Pattern&) = default;
    };

    void collect_pattern(Pattern pattern);
    static std::vector<Pattern> aggregate(PatternAggregator aggregator);

    static constexpr size_t kMaxPatterns = 64 * 1024;

  private:
    std::unique_ptr<PatternAggregatorImpl> p_impl_;
};

}  // namespace silkworm::snapshots::seg
