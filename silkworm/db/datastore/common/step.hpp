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
