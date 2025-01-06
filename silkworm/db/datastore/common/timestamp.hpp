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
#include <string>

namespace silkworm::datastore {

using Timestamp = uint64_t;

struct TimestampRange {
    Timestamp start;
    Timestamp end;
    TimestampRange(Timestamp start1, Timestamp end1) : start(start1), end(end1) {}
    friend bool operator==(const TimestampRange&, const TimestampRange&) = default;
    bool contains(Timestamp value) const { return (start <= value) && (value < end); }
    auto contains_predicate() {
        return [range = *this](Timestamp t) { return range.contains(t); };
    };
    bool contains_range(TimestampRange range) const { return (start <= range.start) && (range.end <= end); }
    Timestamp size() const { return end - start; }
    std::string to_string() const { return std::string("[") + std::to_string(start) + ", " + std::to_string(end) + ")"; }
};

}  // namespace silkworm::datastore
