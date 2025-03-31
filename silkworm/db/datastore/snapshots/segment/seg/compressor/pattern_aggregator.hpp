// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
    explicit PatternAggregator(const std::filesystem::path& etl_work_path);
    ~PatternAggregator();

    PatternAggregator(PatternAggregator&& other) noexcept;
    PatternAggregator& operator=(PatternAggregator&& other) noexcept;

    struct Pattern {
        Bytes data;
        uint64_t score{0};

        friend bool operator==(const Pattern&, const Pattern&) = default;
    };

    void collect_pattern(Pattern pattern);
    static std::vector<Pattern> aggregate(PatternAggregator aggregator);

    static constexpr size_t kMaxPatterns = 64 * 1024;

  private:
    std::unique_ptr<PatternAggregatorImpl> p_impl_;
};

}  // namespace silkworm::snapshots::seg
