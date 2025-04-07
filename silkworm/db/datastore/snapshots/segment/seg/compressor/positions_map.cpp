// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
    ++uses_[kTerminatorPosition];  // total word count
    ++uses_[word_length_position(raw_word_length)];

    size_t prev_pos = 0;
    for (auto& pattern_position : pattern_positions) {
        ++uses_[position(pattern_position.first, prev_pos)];
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
