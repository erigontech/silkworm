// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

namespace silkworm::snapshots::seg {

class PositionsMap {
  public:
    void update_with_word(
        size_t raw_word_length,
        const std::vector<std::pair<size_t, size_t>>& pattern_positions);

    std::vector<uint64_t> list_positions();
    std::vector<uint64_t> list_uses();

    static size_t position(size_t pattern_position, size_t prev_pattern_position);
    static size_t word_length_position(size_t word_length);
    static constexpr size_t kTerminatorPosition = 0;

  private:
    std::map<size_t, uint64_t> uses_;
};

}  // namespace silkworm::snapshots::seg
