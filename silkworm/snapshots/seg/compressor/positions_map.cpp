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

#include "positions_map.hpp"

namespace silkworm::snapshots::seg {

size_t PositionsMap::position(size_t pattern_position, size_t prev_pattern_position) {
    return pattern_position - prev_pattern_position + 1;
}

size_t PositionsMap::word_length_position(size_t word_length) {
    return word_length + 1;
}

void PositionsMap::update_with_word(
    size_t raw_word_length,
    const std::vector<std::pair<size_t, size_t>>& pattern_positions) {
    uses_[kTerminatorPosition]++;  // total word count
    uses_[word_length_position(raw_word_length)]++;

    size_t prev_pos = 0;
    for (auto& pattern_position : pattern_positions) {
        uses_[position(pattern_position.first, prev_pos)]++;
        prev_pos = pattern_position.first;
    }
}

std::vector<uint64_t> PositionsMap::list_positions() {
    std::vector<uint64_t> result;
    result.reserve(uses_.size());
    for (auto& entry : uses_)
        result.push_back(static_cast<uint64_t>(entry.first));
    return result;
}

std::vector<uint64_t> PositionsMap::list_uses() {
    std::vector<uint64_t> result;
    result.reserve(uses_.size());
    for (auto& entry : uses_)
        result.push_back(entry.second);
    return result;
}

}  // namespace silkworm::snapshots::seg
