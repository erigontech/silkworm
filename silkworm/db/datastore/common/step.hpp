// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <limits>
#include <string>

#include <silkworm/infra/common/ensure.hpp>

namespace silkworm::datastore {

struct Step {
    size_t value;

    constexpr explicit Step(size_t value1) : value(value1) {}
    friend bool operator==(const Step&, const Step&) = default;
    bool operator<(const Step& other) const { return this->value < other.value; }
    bool operator<=(const Step& other) const { return this->value <= other.value; }
    std::string to_string() const { return std::to_string(value) + "st"; }
};

inline constexpr Step kMaxStep{std::numeric_limits<size_t>::max()};

struct StepRange {
    Step start;
    Step end;

    StepRange(Step start1, Step end1) : start(start1), end(end1) {
        ensure(start <= end, "StepRange: end before start");
    }
    friend bool operator==(const StepRange&, const StepRange&) = default;
    bool contains(Step x) const { return (start <= x) && (x < end); }
    bool contains_range(StepRange range) const { return (start <= range.start) && (range.end <= end); }
    size_t size() const { return end.value - start.value; }
    std::string to_string() const { return std::string("[") + start.to_string() + ", " + end.to_string() + ")"; }
};

}  // namespace silkworm::datastore
