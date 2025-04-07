// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <limits>
#include <string>

namespace silkworm::datastore {

using Timestamp = uint64_t;

inline constexpr Timestamp kMaxTimestamp = std::numeric_limits<Timestamp>::max();

struct TimestampRange {
    Timestamp start;
    Timestamp end;
    TimestampRange(Timestamp start1, Timestamp end1) : start(start1), end(end1) {}
    friend bool operator==(const TimestampRange&, const TimestampRange&) = default;
    bool contains(Timestamp value) const { return (start <= value) && (value < end); }
    auto contains_predicate() const {
        return [range = *this](Timestamp t) { return range.contains(t); };
    };
    bool contains_range(TimestampRange range) const { return (start <= range.start) && (range.end <= end); }
    Timestamp size() const { return end - start; }
    std::string to_string() const { return std::string("[") + std::to_string(start) + ", " + std::to_string(end) + ")"; }
};

}  // namespace silkworm::datastore
